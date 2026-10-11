use regex::Regex;
use std::net::SocketAddr;
use std::time::Duration;
use syslogcat::proto::{Facility, Severity};
use syslogcat::{
    format_syslog_display, format_syslog_ndjson, SyslogFilter, SyslogServer, Transport,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::test]
async fn test_live_udp_and_tcp_syslog_server() {
    // Find an ephemeral port that can bind both UDP and TCP
    let dummy_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind_addr = dummy_tcp.local_addr().unwrap();
    drop(dummy_tcp);

    let (server, mut rx) = SyslogServer::start(bind_addr, true, true).await.unwrap();

    // 1. Send RFC 5424 over UDP
    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rfc5424_msg = b"<165>1 2026-09-25T13:20:15.000Z edge-router-01 firewall - ID99 [netflow@32473 src=\"10.0.0.5\" dst=\"1.1.1.1\"] Packet dropped";
    udp_client.send_to(rfc5424_msg, bind_addr).await.unwrap();

    let event_udp = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("Timeout receiving UDP syslog")
        .expect("Expected UDP event");

    assert_eq!(event_udp.transport, Transport::Udp);
    assert_eq!(event_udp.syslog.priority, 165);
    assert_eq!(event_udp.syslog.facility, Facility::Local4);
    assert_eq!(event_udp.syslog.severity, Severity::Notice);
    assert_eq!(event_udp.syslog.hostname.as_deref(), Some("edge-router-01"));
    assert_eq!(event_udp.syslog.app_name.as_deref(), Some("firewall"));
    assert_eq!(event_udp.syslog.msg_id.as_deref(), Some("ID99"));
    assert_eq!(event_udp.syslog.message, "Packet dropped");

    let sd = event_udp
        .syslog
        .structured_data
        .get("netflow@32473")
        .unwrap();
    assert_eq!(sd.get("src").map(String::as_str), Some("10.0.0.5"));
    assert_eq!(sd.get("dst").map(String::as_str), Some("1.1.1.1"));

    // Verify formatters
    let display = format_syslog_display(&event_udp, false);
    assert!(display.contains("local4.notice"));
    assert!(display.contains("Packet dropped"));

    let ndjson = format_syslog_ndjson(&event_udp).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&ndjson).unwrap();
    assert_eq!(parsed["facility"], "local4");
    assert_eq!(parsed["severity"], "notice");
    assert_eq!(parsed["message"], "Packet dropped");

    // 2. Send RFC 3164 over TCP
    let mut tcp_client = TcpStream::connect(bind_addr).await.unwrap();
    let rfc3164_msg = b"<34>Oct 11 22:14:15 srv01 nginx[404]: GET /api/v1/health 200\n";
    tcp_client.write_all(rfc3164_msg).await.unwrap();

    let event_tcp = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("Timeout receiving TCP syslog")
        .expect("Expected TCP event");

    assert_eq!(event_tcp.transport, Transport::Tcp);
    assert_eq!(event_tcp.syslog.priority, 34);
    assert_eq!(event_tcp.syslog.facility, Facility::Auth);
    assert_eq!(event_tcp.syslog.severity, Severity::Critical);
    assert_eq!(event_tcp.syslog.hostname.as_deref(), Some("srv01"));
    assert_eq!(event_tcp.syslog.app_name.as_deref(), Some("nginx"));
    assert_eq!(event_tcp.syslog.proc_id.as_deref(), Some("404"));
    assert_eq!(event_tcp.syslog.message, "GET /api/v1/health 200");

    server.stop();
}

#[test]
fn test_syslog_filtering() {
    let filter = SyslogFilter {
        min_severity: Some(Severity::Warning), // severity <= 4 (emerg..warning)
        facilities: vec![Facility::Auth, Facility::Authpriv],
        app_regex: Some(Regex::new(r"^sshd$").unwrap()),
        msg_regex: Some(Regex::new(r"failed").unwrap()),
    };

    let pass_raw = "<35>Oct 11 22:14:15 host sshd[100]: Password authentication failed";
    let pass_syslog = syslogcat::proto::parse_syslog(pass_raw).unwrap();
    let pass_event = syslogcat::SyslogEvent {
        syslog: pass_syslog,
        transport: Transport::Udp,
        source_addr: "127.0.0.1:5140".parse::<SocketAddr>().unwrap(),
        received_at: "2026-09-25T13:20:15Z".to_string(),
    };
    // 35 / 8 = 4 (auth), 35 % 8 = 3 (error <= warning)
    assert!(filter.matches(&pass_event));

    // Reject due to severity too low (Notice = 5 > 4)
    let reject_sev_raw = "<37>Oct 11 22:14:15 host sshd[100]: Password authentication failed";
    let reject_sev_syslog = syslogcat::proto::parse_syslog(reject_sev_raw).unwrap();
    let reject_sev_event = syslogcat::SyslogEvent {
        syslog: reject_sev_syslog,
        transport: Transport::Udp,
        source_addr: "127.0.0.1:5140".parse::<SocketAddr>().unwrap(),
        received_at: "2026-09-25T13:20:15Z".to_string(),
    };
    assert!(!filter.matches(&reject_sev_event));

    // Reject due to wrong facility (Daemon = 3)
    let reject_fac_raw = "<27>Oct 11 22:14:15 host sshd[100]: Password authentication failed";
    let reject_fac_syslog = syslogcat::proto::parse_syslog(reject_fac_raw).unwrap();
    let reject_fac_event = syslogcat::SyslogEvent {
        syslog: reject_fac_syslog,
        transport: Transport::Udp,
        source_addr: "127.0.0.1:5140".parse::<SocketAddr>().unwrap(),
        received_at: "2026-09-25T13:20:15Z".to_string(),
    };
    assert!(!filter.matches(&reject_fac_event));
}
