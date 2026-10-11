use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use regex::Regex;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use syslogcat::proto::{encode_rfc3164, encode_rfc5424, Facility, Severity};
use syslogcat::{
    format_syslog_display, format_syslog_ndjson, SyslogFilter, SyslogServer,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProtocolChoice {
    Both,
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RfcChoice {
    #[value(name = "5424")]
    Rfc5424,
    #[value(name = "3164")]
    Rfc3164,
}

#[derive(Parser, Debug)]
#[command(
    name = "syslogcat",
    about = "Fast, standalone RFC 5424 & RFC 3164 Syslog receiver, parser, filter, and stream processor",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    listen_defaults: ListenArgs,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Listen for incoming Syslog messages on UDP/TCP (default)
    Listen(ListenArgs),
    /// Emit a synthetic Syslog message to a target server
    Emit(EmitArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct ListenArgs {
    /// Address and port to bind listener on (e.g. "0.0.0.0:5140" or ":514")
    #[arg(short, long, default_value = "0.0.0.0:5140")]
    bind: String,

    /// Transport protocol to listen on (both, udp, tcp)
    #[arg(long, value_enum, default_value_t = ProtocolChoice::Both)]
    proto: ProtocolChoice,

    /// Minimum severity threshold (emerg, alert, crit, err, warning, notice, info, debug)
    #[arg(short = 's', long)]
    min_severity: Option<String>,

    /// Filter by syslog facility (e.g. auth, daemon, local0, etc. Can specify multiple)
    #[arg(short = 'f', long)]
    facility: Vec<String>,

    /// Filter by application name regex
    #[arg(short = 'a', long)]
    app: Option<String>,

    /// Filter by message content regex
    #[arg(short = 'm', long)]
    message: Option<String>,

    /// Output messages as NDJSON (JSON Lines) with complete parsed metadata
    #[arg(short = 'j', long)]
    ndjson: bool,

    /// Exit after receiving N matching messages
    #[arg(short = 'n', long)]
    count: Option<u64>,

    /// Disable ANSI color formatting
    #[arg(long)]
    no_color: bool,
}

impl Default for ListenArgs {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:5140".to_string(),
            proto: ProtocolChoice::Both,
            min_severity: None,
            facility: Vec::new(),
            app: None,
            message: None,
            ndjson: false,
            count: None,
            no_color: false,
        }
    }
}

#[derive(Parser, Debug)]
pub struct EmitArgs {
    /// Target syslog server address (e.g. "127.0.0.1:5140")
    #[arg(short, long, default_value = "127.0.0.1:5140")]
    target: String,

    /// Transport protocol (udp or tcp)
    #[arg(long, default_value = "udp")]
    proto: String,

    /// Syslog standard format (5424 or 3164)
    #[arg(long, value_enum, default_value_t = RfcChoice::Rfc5424)]
    rfc: RfcChoice,

    /// Syslog facility (e.g. user, local0, auth, daemon)
    #[arg(short = 'f', long, default_value = "user")]
    facility: String,

    /// Syslog severity (emerg, alert, crit, err, warning, notice, info, debug)
    #[arg(short = 's', long, default_value = "info")]
    severity: String,

    /// Hostname to report
    #[arg(short = 'H', long, default_value = "localhost")]
    hostname: String,

    /// Application or tag name
    #[arg(short = 'a', long, default_value = "syslogcat")]
    app: String,

    /// Process ID
    #[arg(long)]
    proc_id: Option<String>,

    /// Message ID (RFC 5424 only)
    #[arg(long)]
    msg_id: Option<String>,

    /// Log message payload
    #[arg(short = 'm', long)]
    message: String,

    /// Number of messages to emit
    #[arg(short = 'n', long, default_value_t = 1)]
    count: u64,

    /// Emission rate limit in messages per second (0 for unlimited)
    #[arg(long, default_value_t = 0)]
    rate: u64,
}

fn resolve_addr(addr_str: &str) -> Result<SocketAddr> {
    let normalized = if addr_str.starts_with(':') {
        format!("0.0.0.0{}", addr_str)
    } else {
        addr_str.to_string()
    };

    use std::net::ToSocketAddrs;
    let mut addrs = normalized
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve bind address '{}'", addr_str))?;

    addrs
        .next()
        .context(format!("No IP address found for '{}'", addr_str))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Listen(args)) => run_listen(args).await,
        Some(Commands::Emit(args)) => run_emit(args).await,
        None => run_listen(cli.listen_defaults).await,
    }
}

async fn run_listen(args: ListenArgs) -> Result<()> {
    if args.no_color {
        colored::control::set_override(false);
    }

    let bind_addr = resolve_addr(&args.bind)?;

    let min_severity = if let Some(ref s) = args.min_severity {
        Some(
            Severity::from_name(s)
                .context(format!("Unknown syslog severity level '{}'", s))?,
        )
    } else {
        None
    };

    let mut facilities = Vec::new();
    for f in &args.facility {
        for fac_name in f.split(',') {
            let fac_trimmed = fac_name.trim();
            if !fac_trimmed.is_empty() {
                let fac = Facility::from_name(fac_trimmed)
                    .context(format!("Unknown syslog facility '{}'", fac_trimmed))?;
                facilities.push(fac);
            }
        }
    }

    let app_regex = match args.app {
        Some(ref pat) => Some(Regex::new(pat).context("Invalid --app regex pattern")?),
        None => None,
    };

    let msg_regex = match args.message {
        Some(ref pat) => Some(Regex::new(pat).context("Invalid --message regex pattern")?),
        None => None,
    };

    let filter = SyslogFilter {
        min_severity,
        facilities,
        app_regex,
        msg_regex,
    };

    let (enable_udp, enable_tcp) = match args.proto {
        ProtocolChoice::Both => (true, true),
        ProtocolChoice::Udp => (true, false),
        ProtocolChoice::Tcp => (false, true),
    };

    eprintln!(
        "{} Listening for Syslog on {} (UDP: {}, TCP: {})...",
        "●".cyan(),
        bind_addr.to_string().bold(),
        if enable_udp { "active".green() } else { "off".dimmed() },
        if enable_tcp { "active".green() } else { "off".dimmed() }
    );

    let (server, mut rx) = SyslogServer::start(bind_addr, enable_udp, enable_tcp).await?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        r.store(false, Ordering::SeqCst);
    });

    let mut count = 0u64;
    let mut stdout = io::stdout().lock();

    while running.load(Ordering::SeqCst) {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(event)) => {
                if !filter.matches(&event) {
                    continue;
                }

                count += 1;

                if args.ndjson {
                    let json = format_syslog_ndjson(&event)?;
                    writeln!(stdout, "{}", json)?;
                } else {
                    let display = format_syslog_display(&event, !args.no_color);
                    writeln!(stdout, "{}", display)?;
                }
                stdout.flush()?;

                if let Some(limit) = args.count {
                    if count >= limit {
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    server.stop();
    Ok(())
}

async fn run_emit(args: EmitArgs) -> Result<()> {
    let target_addr = resolve_addr(&args.target)?;

    let facility = Facility::from_name(&args.facility)
        .context(format!("Unknown syslog facility '{}'", args.facility))?;
    let severity = Severity::from_name(&args.severity)
        .context(format!("Unknown syslog severity '{}'", args.severity))?;

    let payload = match args.rfc {
        RfcChoice::Rfc5424 => encode_rfc5424(
            facility,
            severity,
            &args.hostname,
            &args.app,
            args.proc_id.as_deref(),
            args.msg_id.as_deref(),
            None,
            &args.message,
        ),
        RfcChoice::Rfc3164 => encode_rfc3164(
            facility,
            severity,
            &args.hostname,
            &args.app,
            &args.message,
        ),
    };

    let delay = if args.rate > 0 {
        Some(Duration::from_secs_f64(1.0 / (args.rate as f64)))
    } else {
        None
    };

    let is_tcp = args.proto.eq_ignore_ascii_case("tcp");

    eprintln!(
        "{} Emitting {} syslog message(s) ({}) to {} via {}...",
        "●".cyan(),
        args.count,
        match args.rfc {
            RfcChoice::Rfc5424 => "RFC 5424",
            RfcChoice::Rfc3164 => "RFC 3164",
        },
        target_addr,
        if is_tcp { "TCP" } else { "UDP" }
    );

    if is_tcp {
        let mut stream = TcpStream::connect(target_addr)
            .await
            .with_context(|| format!("Failed to connect TCP stream to {}", target_addr))?;

        let mut framed_msg = payload.clone();
        framed_msg.push('\n');
        let bytes = framed_msg.as_bytes();

        for i in 0..args.count {
            stream
                .write_all(bytes)
                .await
                .with_context(|| format!("Failed to send TCP message #{}", i + 1))?;

            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
        }
    } else {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP client socket")?;

        let bytes = payload.as_bytes();

        for i in 0..args.count {
            socket
                .send_to(bytes, target_addr)
                .await
                .with_context(|| format!("Failed to send UDP datagram #{}", i + 1))?;

            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
        }
    }

    eprintln!(
        "{} Successfully transmitted {} message(s)",
        "✔".green(),
        args.count
    );
    Ok(())
}
