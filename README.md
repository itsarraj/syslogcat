# syslogcat

A fast, lightweight, standalone RFC 5424 & RFC 3164 Syslog receiver, parser, filter, and stream processor (UDP & TCP).

`syslogcat` gives network engineers, SREs, and backend developers an immediate, zero-configuration CLI tool for debugging Syslog telemetry from firewalls, switches (Cisco, Ubiquiti), hypervisors, and Docker/Kubernetes logging drivers without wrestling with `nc -ul 514` or configuring heavy daemons (`rsyslog`, `syslog-ng`, `vector`).

---

## Status

**Status: Complete & Verified**
- Verified live dual-protocol server (UDP datagrams and TCP octet-counted / newline-delimited framing) against real local sockets.
- Full protocol parser for modern RFC 5424 (ISO 8601 timestamps, structured data `[sd-id key="val"]`, app name, proc ID, msg ID) and legacy RFC 3164 (BSD syslog tags `app[pid]:`).
- Severity and facility filtering verified against real log events.
- Formatted visual logs with colored severity badges and structured NDJSON output verified.
- Synthetic syslog generator (`syslogcat emit`) verified across UDP and TCP.
- *Deferred*: TLS wrapping (RFC 5425 mutual TLS) is reserved for a future release.

---

## Features

- **Zero Daemons / Zero Root**: Runs as an unprivileged standalone binary listening on UDP and TCP (default port `5140`, or `514` if root).
- **Dual RFC Support**:
  - **RFC 5424 (Modern)**: Parses version, structured data key-values, message IDs, and ISO 8601 timestamps.
  - **RFC 3164 (Legacy BSD)**: Parses traditional BSD timestamp headers and application tags `tag[pid]:`.
- **Dual Transport (UDP & TCP)**: Concurrent receiver for UDP datagrams and TCP streams with RFC 6587 octet-counting and newline/NUL delimiters.
- **Precision Filtering**:
  - Filter by minimum severity threshold: `--min-severity warning` (captures `emerg`, `alert`, `crit`, `err`, `warning`)
  - Filter by facility: `--facility auth,authpriv,daemon`
  - Filter by application regex: `--app "^(nginx|sshd)$"`
  - Filter by message content regex: `--message "authentication failed"`
- **Structured NDJSON Streaming**: Stream single-line JSON (`-j` / `--ndjson`) directly to `jq`, ClickHouse, or vector databases.
- **Synthetic Log Generator (`syslogcat emit`)**: Transmit single or rate-paced RFC 5424 or RFC 3164 test syslog messages over UDP or TCP.

---

## Installation

```bash
cargo install --path .
```

---

## Usage

### 1. Receive and Stream Logs

Listen on default port `5140` across both UDP and TCP:
```bash
syslogcat
```

Bind to standard privileged port `514` (requires root or `setcap`):
```bash
sudo syslogcat -b 0.0.0.0:514
```

Listen only on TCP:
```bash
syslogcat --proto tcp -b 127.0.0.1:5140
```

### 2. Filtering

Filter for warnings, errors, and critical alerts only:
```bash
syslogcat --min-severity warning
```

Filter for authentication and security facilities:
```bash
syslogcat -f auth,authpriv
```

Filter for specific applications and messages:
```bash
syslogcat -a "^sshd$" -m "Failed password"
```

Stream as NDJSON and pipe to `jq`:
```bash
syslogcat -j | jq '{host: .hostname, app: .app_name, msg: .message}'
```

Exit after receiving 10 matching messages:
```bash
syslogcat -n 10
```

### 3. Emitting Synthetic Syslog Messages

Send an RFC 5424 warning message over UDP:
```bash
syslogcat emit -t 127.0.0.1:5140 -f local0 -s warning -a "edge-gw" -m "BGP session down"
```

Send an RFC 3164 critical message over TCP:
```bash
syslogcat emit -t 127.0.0.1:5140 --proto tcp --rfc 3164 -f auth -s crit -a "sudo" -m "PAM auth failed"
```

---

## CLI Reference

### `syslogcat listen`
| Flag | Description | Default |
|---|---|---|
| `-b, --bind <ADDR>` | Bind address and port | `0.0.0.0:5140` |
| `--proto <PROTO>` | Transport protocol: `both`, `udp`, `tcp` | `both` |
| `-s, --min-severity <SEV>` | Minimum severity threshold | All |
| `-f, --facility <FAC>` | Facilities to accept (repeatable or comma-separated) | All |
| `-a, --app <REGEX>` | Application name filter regex | None |
| `-m, --message <REGEX>` | Message content filter regex | None |
| `-j, --ndjson` | Emit single-line JSON (NDJSON) | False |
| `-n, --count <N>` | Exit after receiving N matching messages | Unlimited |
| `--no-color` | Disable ANSI color highlighting | Color enabled |

### `syslogcat emit`
| Flag | Description | Default |
|---|---|---|
| `-t, --target <ADDR>` | Target server socket address | `127.0.0.1:5140` |
| `--proto <PROTO>` | Transport protocol (`udp` or `tcp`) | `udp` |
| `--rfc <VERSION>` | Format standard: `5424` or `3164` | `5424` |
| `-f, --facility <FAC>` | Syslog facility name | `user` |
| `-s, --severity <SEV>` | Syslog severity level | `info` |
| `-H, --hostname <HOST>` | Originating hostname | `localhost` |
| `-a, --app <APP>` | Application tag | `syslogcat` |
| `-m, --message <MSG>` | Message body text | Required |
| `-n, --count <N>` | Number of messages to transmit | `1` |
| `--rate <PPS>` | Packets per second rate limit (0 = max speed) | `0` |

---

## License

MIT License. Copyright (c) 2026 Animesh Raj.
