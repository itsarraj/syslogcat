use anyhow::{Context, Result};
use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

pub mod proto;

pub use proto::{Facility, ParsedSyslog, RfcVersion, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyslogEvent {
    #[serde(flatten)]
    pub syslog: ParsedSyslog,
    pub transport: Transport,
    pub source_addr: SocketAddr,
    pub received_at: String,
}

#[derive(Debug, Clone)]
pub struct SyslogFilter {
    pub min_severity: Option<Severity>,
    pub facilities: Vec<Facility>,
    pub app_regex: Option<Regex>,
    pub msg_regex: Option<Regex>,
}

impl SyslogFilter {
    pub fn matches(&self, event: &SyslogEvent) -> bool {
        // Lower numeric value = higher severity (0 = emerg, 7 = debug)
        if let Some(min_sev) = self.min_severity {
            if event.syslog.severity.code() > min_sev.code() {
                return false;
            }
        }

        if !self.facilities.is_empty() && !self.facilities.contains(&event.syslog.facility) {
            return false;
        }

        if let Some(ref re) = self.app_regex {
            let app = event.syslog.app_name.as_deref().unwrap_or("");
            if !re.is_match(app) {
                return false;
            }
        }

        if let Some(ref re) = self.msg_regex {
            if !re.is_match(&event.syslog.message) {
                return false;
            }
        }

        true
    }
}

pub fn format_syslog_display(event: &SyslogEvent, color: bool) -> String {
    let ts = event
        .syslog
        .timestamp
        .as_deref()
        .unwrap_or(&event.received_at);

    let ts_styled = if color {
        format!("[{}]", ts).dimmed().to_string()
    } else {
        format!("[{}]", ts)
    };

    let badge = event.syslog.severity.badge(color);

    let fac_sev = format!("{}.{}", event.syslog.facility.as_str(), event.syslog.severity.as_str());
    let fac_sev_styled = if color {
        format!("[{}]", fac_sev).bold().cyan().to_string()
    } else {
        format!("[{}]", fac_sev)
    };

    let proto_str = match event.transport {
        Transport::Udp => "UDP",
        Transport::Tcp => "TCP",
    };
    let src_info = if color {
        format!("({} {})", proto_str, event.source_addr).dimmed().to_string()
    } else {
        format!("({} {})", proto_str, event.source_addr)
    };

    let mut prefix_parts = Vec::new();
    if let Some(ref host) = event.syslog.hostname {
        prefix_parts.push(host.clone());
    }

    let mut tag_part = String::new();
    if let Some(ref app) = event.syslog.app_name {
        tag_part.push_str(app);
        if let Some(ref pid) = event.syslog.proc_id {
            tag_part.push('[');
            tag_part.push_str(pid);
            tag_part.push(']');
        }
        tag_part.push(':');
    }
    if !tag_part.is_empty() {
        prefix_parts.push(tag_part);
    }

    let origin = if !prefix_parts.is_empty() {
        format!("{} ", prefix_parts.join(" "))
    } else {
        String::new()
    };

    let mut line = format!(
        "{} {} {} {} {}{}",
        ts_styled, badge, fac_sev_styled, src_info, origin, event.syslog.message
    );

    if !event.syslog.structured_data.is_empty() {
        for (id, params) in &event.syslog.structured_data {
            let mut sd_items: Vec<String> = params
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            sd_items.sort();
            let sd_str = format!("\n    [{} {}]", id, sd_items.join(" "));
            if color {
                line.push_str(&sd_str.dimmed().to_string());
            } else {
                line.push_str(&sd_str);
            }
        }
    }

    line
}

pub fn format_syslog_ndjson(event: &SyslogEvent) -> Result<String> {
    Ok(serde_json::to_string(event)?)
}

pub struct SyslogServer {
    running: Arc<AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SyslogServer {
    pub async fn start(
        bind_addr: SocketAddr,
        enable_udp: bool,
        enable_tcp: bool,
    ) -> Result<(Self, mpsc::Receiver<SyslogEvent>)> {
        let (tx, rx) = mpsc::channel(1024);
        let running = Arc::new(AtomicBool::new(true));
        let mut tasks = Vec::new();

        if enable_udp {
            let udp_socket = UdpSocket::bind(bind_addr)
                .await
                .with_context(|| format!("Failed to bind UDP socket on {}", bind_addr))?;

            let tx_udp = tx.clone();
            let running_udp = running.clone();

            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while running_udp.load(Ordering::SeqCst) {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        udp_socket.recv_from(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok((n, from))) => {
                            if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                                for line in text.lines() {
                                    if line.trim().is_empty() {
                                        continue;
                                    }
                                    if let Ok(parsed) = proto::parse_syslog(line) {
                                        let event = SyslogEvent {
                                            syslog: parsed,
                                            transport: Transport::Udp,
                                            source_addr: from,
                                            received_at: chrono::Utc::now().to_rfc3339(),
                                        };
                                        if tx_udp.send(event).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => continue,
                    }
                }
            });
            tasks.push(task);
        }

        if enable_tcp {
            let tcp_listener = TcpListener::bind(bind_addr)
                .await
                .with_context(|| format!("Failed to bind TCP listener on {}", bind_addr))?;

            let tx_tcp = tx.clone();
            let running_tcp = running.clone();

            let task = tokio::spawn(async move {
                while running_tcp.load(Ordering::SeqCst) {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        tcp_listener.accept(),
                    )
                    .await
                    {
                        Ok(Ok((mut socket, from))) => {
                            let tx_conn = tx_tcp.clone();
                            let running_conn = running_tcp.clone();

                            tokio::spawn(async move {
                                let mut buffer = Vec::new();
                                let mut temp = [0u8; 4096];

                                while running_conn.load(Ordering::SeqCst) {
                                    match socket.read(&mut temp).await {
                                        Ok(0) => break, // EOF
                                        Ok(n) => {
                                            buffer.extend_from_slice(&temp[..n]);
                                            let frames = proto::extract_tcp_frames(&mut buffer);
                                            for frame in frames {
                                                if let Ok(text) = std::str::from_utf8(&frame) {
                                                    if let Ok(parsed) = proto::parse_syslog(text) {
                                                        let event = SyslogEvent {
                                                            syslog: parsed,
                                                            transport: Transport::Tcp,
                                                            source_addr: from,
                                                            received_at: chrono::Utc::now()
                                                                .to_rfc3339(),
                                                        };
                                                        if tx_conn.send(event).await.is_err() {
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                        Ok(Err(_)) => break,
                        Err(_) => continue,
                    }
                }
            });
            tasks.push(task);
        }

        Ok((Self { running, tasks }, rx))
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for SyslogServer {
    fn drop(&mut self) {
        self.stop();
    }
}
