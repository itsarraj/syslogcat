use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Facility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Ntp,
    Security,
    Console,
    SolarisCron,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
    Unknown(u8),
}

impl Facility {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Facility::Kern,
            1 => Facility::User,
            2 => Facility::Mail,
            3 => Facility::Daemon,
            4 => Facility::Auth,
            5 => Facility::Syslog,
            6 => Facility::Lpr,
            7 => Facility::News,
            8 => Facility::Uucp,
            9 => Facility::Cron,
            10 => Facility::Authpriv,
            11 => Facility::Ftp,
            12 => Facility::Ntp,
            13 => Facility::Security,
            14 => Facility::Console,
            15 => Facility::SolarisCron,
            16 => Facility::Local0,
            17 => Facility::Local1,
            18 => Facility::Local2,
            19 => Facility::Local3,
            20 => Facility::Local4,
            21 => Facility::Local5,
            22 => Facility::Local6,
            23 => Facility::Local7,
            other => Facility::Unknown(other),
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            Facility::Kern => 0,
            Facility::User => 1,
            Facility::Mail => 2,
            Facility::Daemon => 3,
            Facility::Auth => 4,
            Facility::Syslog => 5,
            Facility::Lpr => 6,
            Facility::News => 7,
            Facility::Uucp => 8,
            Facility::Cron => 9,
            Facility::Authpriv => 10,
            Facility::Ftp => 11,
            Facility::Ntp => 12,
            Facility::Security => 13,
            Facility::Console => 14,
            Facility::SolarisCron => 15,
            Facility::Local0 => 16,
            Facility::Local1 => 17,
            Facility::Local2 => 18,
            Facility::Local3 => 19,
            Facility::Local4 => 20,
            Facility::Local5 => 21,
            Facility::Local6 => 22,
            Facility::Local7 => 23,
            Facility::Unknown(c) => *c,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Facility::Kern => "kern",
            Facility::User => "user",
            Facility::Mail => "mail",
            Facility::Daemon => "daemon",
            Facility::Auth => "auth",
            Facility::Syslog => "syslog",
            Facility::Lpr => "lpr",
            Facility::News => "news",
            Facility::Uucp => "uucp",
            Facility::Cron => "cron",
            Facility::Authpriv => "authpriv",
            Facility::Ftp => "ftp",
            Facility::Ntp => "ntp",
            Facility::Security => "security",
            Facility::Console => "console",
            Facility::SolarisCron => "solaris-cron",
            Facility::Local0 => "local0",
            Facility::Local1 => "local1",
            Facility::Local2 => "local2",
            Facility::Local3 => "local3",
            Facility::Local4 => "local4",
            Facility::Local5 => "local5",
            Facility::Local6 => "local6",
            Facility::Local7 => "local7",
            Facility::Unknown(_) => "unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "kern" | "kernel" => Some(Facility::Kern),
            "user" => Some(Facility::User),
            "mail" => Some(Facility::Mail),
            "daemon" => Some(Facility::Daemon),
            "auth" => Some(Facility::Auth),
            "syslog" => Some(Facility::Syslog),
            "lpr" => Some(Facility::Lpr),
            "news" => Some(Facility::News),
            "uucp" => Some(Facility::Uucp),
            "cron" => Some(Facility::Cron),
            "authpriv" => Some(Facility::Authpriv),
            "ftp" => Some(Facility::Ftp),
            "ntp" => Some(Facility::Ntp),
            "security" => Some(Facility::Security),
            "console" => Some(Facility::Console),
            "solaris-cron" => Some(Facility::SolarisCron),
            "local0" => Some(Facility::Local0),
            "local1" => Some(Facility::Local1),
            "local2" => Some(Facility::Local2),
            "local3" => Some(Facility::Local3),
            "local4" => Some(Facility::Local4),
            "local5" => Some(Facility::Local5),
            "local6" => Some(Facility::Local6),
            "local7" => Some(Facility::Local7),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
}

impl Severity {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Severity::Emergency,
            1 => Severity::Alert,
            2 => Severity::Critical,
            3 => Severity::Error,
            4 => Severity::Warning,
            5 => Severity::Notice,
            6 => Severity::Informational,
            _ => Severity::Debug,
        }
    }

    pub fn code(&self) -> u8 {
        *self as u8
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Emergency => "emerg",
            Severity::Alert => "alert",
            Severity::Critical => "crit",
            Severity::Error => "err",
            Severity::Warning => "warning",
            Severity::Notice => "notice",
            Severity::Informational => "info",
            Severity::Debug => "debug",
        }
    }

    pub fn badge(&self, color: bool) -> String {
        match self {
            Severity::Emergency => {
                if color {
                    "[EMERG]".on_red().white().bold().to_string()
                } else {
                    "[EMERG]".to_string()
                }
            }
            Severity::Alert => {
                if color {
                    "[ALERT]".red().bold().to_string()
                } else {
                    "[ALERT]".to_string()
                }
            }
            Severity::Critical => {
                if color {
                    "[CRIT]".red().bold().to_string()
                } else {
                    "[CRIT]".to_string()
                }
            }
            Severity::Error => {
                if color {
                    "[ERR]".red().to_string()
                } else {
                    "[ERR]".to_string()
                }
            }
            Severity::Warning => {
                if color {
                    "[WARN]".yellow().to_string()
                } else {
                    "[WARN]".to_string()
                }
            }
            Severity::Notice => {
                if color {
                    "[NOTICE]".cyan().to_string()
                } else {
                    "[NOTICE]".to_string()
                }
            }
            Severity::Informational => {
                if color {
                    "[INFO]".green().to_string()
                } else {
                    "[INFO]".to_string()
                }
            }
            Severity::Debug => {
                if color {
                    "[DEBUG]".dimmed().to_string()
                } else {
                    "[DEBUG]".to_string()
                }
            }
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "emerg" | "emergency" | "0" => Some(Severity::Emergency),
            "alert" | "1" => Some(Severity::Alert),
            "crit" | "critical" | "2" => Some(Severity::Critical),
            "err" | "error" | "3" => Some(Severity::Error),
            "warn" | "warning" | "4" => Some(Severity::Warning),
            "notice" | "5" => Some(Severity::Notice),
            "info" | "informational" | "6" => Some(Severity::Informational),
            "debug" | "7" => Some(Severity::Debug),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfcVersion {
    Rfc5424,
    Rfc3164,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedSyslog {
    pub priority: u8,
    pub facility: Facility,
    pub severity: Severity,
    pub rfc: RfcVersion,
    pub version: Option<u8>,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub proc_id: Option<String>,
    pub msg_id: Option<String>,
    pub structured_data: HashMap<String, HashMap<String, String>>,
    pub message: String,
}

/// Parse RFC 5424 structured data: `[id param="val" ...][id2 ...]`
fn parse_structured_data(
    input: &str,
) -> (HashMap<String, HashMap<String, String>>, usize) {
    let mut map = HashMap::new();
    let mut consumed = 0;
    let chars: Vec<char> = input.chars().collect();

    if chars.is_empty() || chars[0] != '[' {
        return (map, 0);
    }

    let mut i = 0;
    while i < chars.len() && chars[i] == '[' {
        i += 1; // skip '['
        // Read SD-ID
        let mut sd_id = String::new();
        while i < chars.len() && chars[i] != ' ' && chars[i] != ']' {
            sd_id.push(chars[i]);
            i += 1;
        }

        let mut params = HashMap::new();
        while i < chars.len() && chars[i] != ']' {
            if chars[i] == ' ' {
                i += 1;
                continue;
            }

            // Read param name
            let mut param_name = String::new();
            while i < chars.len() && chars[i] != '=' && chars[i] != ']' && chars[i] != ' ' {
                param_name.push(chars[i]);
                i += 1;
            }

            if i < chars.len() && chars[i] == '=' {
                i += 1; // skip '='
                if i < chars.len() && chars[i] == '"' {
                    i += 1; // skip open quote
                    let mut param_val = String::new();
                    let mut escaped = false;
                    while i < chars.len() {
                        let c = chars[i];
                        if escaped {
                            param_val.push(c);
                            escaped = false;
                        } else if c == '\\' {
                            escaped = true;
                        } else if c == '"' {
                            i += 1; // skip close quote
                            break;
                        } else {
                            param_val.push(c);
                        }
                        i += 1;
                    }
                    params.insert(param_name, param_val);
                }
            }
        }

        if i < chars.len() && chars[i] == ']' {
            i += 1; // skip ']'
        }

        if !sd_id.is_empty() {
            map.insert(sd_id, params);
        }
        consumed = i;
    }

    (map, consumed)
}

pub fn parse_syslog(input: &str) -> Result<ParsedSyslog> {
    let input = input.trim_start();
    if !input.starts_with('<') {
        // Fallback for raw message without PRI header
        return Ok(ParsedSyslog {
            priority: 13, // user.notice default
            facility: Facility::User,
            severity: Severity::Notice,
            rfc: RfcVersion::Raw,
            version: None,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: HashMap::new(),
            message: input.trim().to_string(),
        });
    }

    let end_pri = input
        .find('>')
        .context("Missing closing '>' in syslog PRI header")?;
    let pri_str = &input[1..end_pri];
    let priority: u8 = pri_str.parse().context("Invalid numeric PRI value")?;

    let facility = Facility::from_code(priority / 8);
    let severity = Severity::from_code(priority % 8);

    let rest = &input[end_pri + 1..];

    // Check if RFC 5424: starts with version digit and space (e.g. "1 ")
    if rest.len() >= 2
        && rest.as_bytes()[0].is_ascii_digit()
        && rest.as_bytes()[1] == b' '
    {
        parse_rfc5424(priority, facility, severity, rest)
    } else {
        parse_rfc3164(priority, facility, severity, rest)
    }
}

fn parse_rfc5424(
    priority: u8,
    facility: Facility,
    severity: Severity,
    rest: &str,
) -> Result<ParsedSyslog> {
    let mut parts = rest.splitn(7, ' ');

    let version_str = parts.next().unwrap_or("1");
    let version = version_str.parse::<u8>().ok();

    let timestamp_str = parts.next().unwrap_or("-");
    let timestamp = if timestamp_str == "-" {
        None
    } else {
        Some(timestamp_str.to_string())
    };

    let hostname_str = parts.next().unwrap_or("-");
    let hostname = if hostname_str == "-" {
        None
    } else {
        Some(hostname_str.to_string())
    };

    let app_str = parts.next().unwrap_or("-");
    let app_name = if app_str == "-" {
        None
    } else {
        Some(app_str.to_string())
    };

    let proc_str = parts.next().unwrap_or("-");
    let proc_id = if proc_str == "-" {
        None
    } else {
        Some(proc_str.to_string())
    };

    let msg_id_str = parts.next().unwrap_or("-");
    let msg_id = if msg_id_str == "-" {
        None
    } else {
        Some(msg_id_str.to_string())
    };

    let remainder = parts.next().unwrap_or("").trim_start();

    let (structured_data, message) = if remainder.starts_with('[') {
        let (sd, consumed) = parse_structured_data(remainder);
        let msg = remainder[consumed..].trim_start();
        (sd, msg.to_string())
    } else if let Some(m) = remainder.strip_prefix('-') {
        (HashMap::new(), m.trim_start().to_string())
    } else {
        (HashMap::new(), remainder.to_string())
    };

    // Strip optional UTF-8 BOM from message
    let clean_message = message
        .strip_prefix("\u{feff}")
        .unwrap_or(&message)
        .to_string();

    Ok(ParsedSyslog {
        priority,
        facility,
        severity,
        rfc: RfcVersion::Rfc5424,
        version,
        timestamp,
        hostname,
        app_name,
        proc_id,
        msg_id,
        structured_data,
        message: clean_message,
    })
}

fn parse_rfc3164(
    priority: u8,
    facility: Facility,
    severity: Severity,
    rest: &str,
) -> Result<ParsedSyslog> {
    let rest = rest.trim_start();

    // Check for standard BSD timestamp: e.g. "Oct 11 22:14:15"
    let mut tokens = rest.split_whitespace();
    let mut timestamp = None;
    let mut offset = 0;

    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    if let Some(first) = tokens.next() {
        if months.contains(&first) {
            if let Some(day) = tokens.next() {
                if let Some(time) = tokens.next() {
                    let ts = format!("{} {} {}", first, day, time);
                    offset = first.len() + 1 + day.len() + 1 + time.len();
                    timestamp = Some(ts);
                }
            }
        }
    }

    let remainder = if offset > 0 && offset < rest.len() {
        rest[offset..].trim_start()
    } else {
        rest
    };

    // Next token: Hostname (optional) and Tag
    let mut r_tokens = remainder.splitn(2, ' ');
    let first_word = r_tokens.next().unwrap_or("");
    let after_first = r_tokens.next().unwrap_or("");

    let (hostname, tag_and_msg) = if !first_word.ends_with(':') && !after_first.is_empty() {
        (Some(first_word.to_string()), after_first)
    } else {
        (None, remainder)
    };

    // Extract Tag (app_name, proc_id) and message
    let (app_name, proc_id, message) = if let Some(colon_pos) = tag_and_msg.find(':') {
        let tag = &tag_and_msg[..colon_pos].trim();
        let msg = tag_and_msg[colon_pos + 1..].trim();

        if let Some(bracket_start) = tag.find('[') {
            if let Some(bracket_end) = tag.find(']') {
                let app = tag[..bracket_start].to_string();
                let pid = tag[bracket_start + 1..bracket_end].to_string();
                (Some(app), Some(pid), msg.to_string())
            } else {
                (Some(tag.to_string()), None, msg.to_string())
            }
        } else {
            (Some(tag.to_string()), None, msg.to_string())
        }
    } else {
        (None, None, tag_and_msg.to_string())
    };

    Ok(ParsedSyslog {
        priority,
        facility,
        severity,
        rfc: RfcVersion::Rfc3164,
        version: None,
        timestamp,
        hostname,
        app_name,
        proc_id,
        msg_id: None,
        structured_data: HashMap::new(),
        message,
    })
}

/// Extracts complete frames from TCP buffer.
/// Supports RFC 6587 octet counting (`<length> <msg>`) and newline/NUL delimiters.
pub fn extract_tcp_frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();

    loop {
        if buf.is_empty() {
            break;
        }

        // Try octet counting: check if starts with digits followed by space
        let mut digit_len = 0;
        while digit_len < buf.len() && buf[digit_len].is_ascii_digit() {
            digit_len += 1;
        }

        if digit_len > 0 && digit_len < buf.len() && buf[digit_len] == b' ' {
            let len_str = match std::str::from_utf8(&buf[..digit_len]) {
                Ok(s) => s,
                Err(_) => break,
            };
            let frame_len: usize = match len_str.parse() {
                Ok(l) => l,
                Err(_) => break,
            };

            let total_needed = digit_len + 1 + frame_len;
            if buf.len() >= total_needed {
                let frame = buf[digit_len + 1..total_needed].to_vec();
                buf.drain(..total_needed);
                frames.push(frame);
                continue;
            } else {
                // Incomplete frame, wait for more data
                break;
            }
        }

        // Delimiter-based: find \n or \0
        if let Some(pos) = buf.iter().position(|&b| b == b'\n' || b == 0) {
            let frame = buf[..pos].to_vec();
            buf.drain(..pos + 1);
            if !frame.is_empty() {
                frames.push(frame);
            }
        } else {
            // No delimiter found yet
            break;
        }
    }

    frames
}

pub fn encode_rfc5424(
    facility: Facility,
    severity: Severity,
    hostname: &str,
    app_name: &str,
    proc_id: Option<&str>,
    msg_id: Option<&str>,
    structured_data: Option<&[(&str, &[(&str, &str)])]>,
    message: &str,
) -> String {
    let pri = (facility.code() * 8) + severity.code();
    let ts = chrono::Utc::now().to_rfc3339();
    let proc = proc_id.unwrap_or("-");
    let mid = msg_id.unwrap_or("-");

    let sd_str = if let Some(sds) = structured_data {
        if sds.is_empty() {
            "-".to_string()
        } else {
            let mut out = String::new();
            for (id, params) in sds {
                out.push('[');
                out.push_str(id);
                for (k, v) in *params {
                    out.push(' ');
                    out.push_str(k);
                    out.push_str("=\"");
                    out.push_str(v);
                    out.push('"');
                }
                out.push(']');
            }
            out
        }
    } else {
        "-".to_string()
    };

    format!(
        "<{}>1 {} {} {} {} {} {} {}",
        pri, ts, hostname, app_name, proc, mid, sd_str, message
    )
}

pub fn encode_rfc3164(
    facility: Facility,
    severity: Severity,
    hostname: &str,
    tag: &str,
    message: &str,
) -> String {
    let pri = (facility.code() * 8) + severity.code();
    let ts = chrono::Utc::now().format("%b %e %H:%M:%S").to_string();
    format!("<{}>{} {} {}: {}", pri, ts, hostname, tag, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc5424_with_structured_data() {
        let raw = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 101 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] An application event log entry";
        let parsed = parse_syslog(raw).unwrap();

        assert_eq!(parsed.priority, 165);
        assert_eq!(parsed.facility, Facility::Local4); // 165 / 8 = 20 (local4)
        assert_eq!(parsed.severity, Severity::Notice); // 165 % 8 = 5 (notice)
        assert_eq!(parsed.rfc, RfcVersion::Rfc5424);
        assert_eq!(parsed.version, Some(1));
        assert_eq!(
            parsed.timestamp.as_deref(),
            Some("2003-10-11T22:14:15.003Z")
        );
        assert_eq!(parsed.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(parsed.app_name.as_deref(), Some("evntslog"));
        assert_eq!(parsed.proc_id.as_deref(), Some("101"));
        assert_eq!(parsed.msg_id.as_deref(), Some("ID47"));

        let sd = parsed.structured_data.get("exampleSDID@32473").unwrap();
        assert_eq!(sd.get("iut").map(String::as_str), Some("3"));
        assert_eq!(
            sd.get("eventSource").map(String::as_str),
            Some("Application")
        );
        assert_eq!(parsed.message, "An application event log entry");
    }

    #[test]
    fn test_parse_rfc3164_bsd_syslog() {
        let raw = "<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick on /dev/pts/8";
        let parsed = parse_syslog(raw).unwrap();

        assert_eq!(parsed.priority, 34);
        assert_eq!(parsed.facility, Facility::Auth); // 34 / 8 = 4 (auth)
        assert_eq!(parsed.severity, Severity::Critical); // 34 % 8 = 2 (crit)
        assert_eq!(parsed.rfc, RfcVersion::Rfc3164);
        assert_eq!(parsed.hostname.as_deref(), Some("mymachine"));
        assert_eq!(parsed.app_name.as_deref(), Some("su"));
        assert_eq!(parsed.proc_id.as_deref(), Some("1234"));
        assert_eq!(
            parsed.message,
            "'su root' failed for lonvick on /dev/pts/8"
        );
    }

    #[test]
    fn test_extract_tcp_octet_counting() {
        let mut buf = b"24 <34>Oct 11 22:14:15 msg1\n17 <13>1 - - - - - m".to_vec();
        let frames = extract_tcp_frames(&mut buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"<34>Oct 11 22:14:15 msg1");
        assert_eq!(frames[1], b"<13>1 - - - - - m");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_extract_tcp_newline_delimited() {
        let mut buf = b"<34>First message\n<35>Second message\n".to_vec();
        let frames = extract_tcp_frames(&mut buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"<34>First message");
        assert_eq!(frames[1], b"<35>Second message");
        assert!(buf.is_empty());
    }
}
