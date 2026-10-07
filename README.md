# syslog-watch

A lightweight UDP syslog collector with SQLite storage and regex-based alerting.
Point your switches, routers, and Linux servers at it and get a searchable
message archive plus instant alerts on the events that matter.

Built with only the Python standard library — no dependencies to install.

## Features

- **UDP syslog server** (default port `5140`, so no root required; configurable)
- **Parses RFC 3164** (`<PRI>Oct  7 10:30:00 host tag: message`) **and RFC 5424**
  (`<PRI>1 2026-10-07T10:30:00Z host app proc msgid - message`); anything else
  is stored raw — no message is ever lost
- **SQLite storage** (`syslog.db`): every message with timestamp, hostname,
  facility, severity, tag, and message text
- **Regex alerting**: rules in `rules.json` (`{name, pattern, severity}`);
  matches print an `ALERT` to stderr and are recorded in an `alerts` table
- **Daily report** (`--report`): message counts by severity and hostname,
  plus the most-triggered alert rules

## Architecture

```
                         +---------------------------+
  Cisco switch   UDP     |       syslog-watch        |
  --------------+------->|  UDP :5140  (socketserver)|
  Cisco router  UDP     |                           |--> SQLite syslog.db
  --------------+------->|  RFC 3164 / 5424 parser   |      messages, alerts
  Linux server  UDP     |                           |
  --------------+------->|  regex alert engine       |
                         |  (rules.json)             |
                         +-------------+-------------+
                                       |
                              ALERT -> stderr
```

## Quick start

```bash
# Terminal 1 — start the collector
python3 syslog_watch.py

# Terminal 2 — send a burst of realistic demo traffic
python3 send_test_logs.py

# Terminal 1 — print today's summary (Ctrl+C the server first, or use --db)
python3 syslog_watch.py --report
```

## Example session

```
$ python3 syslog_watch.py &
syslog-watch listening on UDP port 5140 (5 alert rules loaded)
database: syslog.db   (Ctrl+C to stop)

$ python3 send_test_logs.py
sent: Oct  7 11:00:01 core-sw-01 %LINK-3-UPDOWN: Interface GigabitEthernet1/0/12, ch
...
done: 15 messages sent to 127.0.0.1:5140

ALERT [Interface up/down] core-sw-01 (err): Interface GigabitEthernet1/0/12, changed state to down
ALERT [SSH failed login] edge-rtr-01 (warning): Login failed [user: admin] [Source: 203.0.113.45] [localport: 22] [Reason: Login Authentication Failed]
ALERT [Configuration change] edge-rtr-01 (notice): Configured from console by admin on vty0 (203.0.113.45)
ALERT [OSPF neighbor change] core-sw-01 (notice): Process 10, Nbr 10.255.1.2 on Vlan20 from FULL to DOWN, Neighbor Down: Dead timer expired
ALERT [Critical severity catch-all] core-sw-01 (crit): Memory allocation of 1024 bytes failed from 0x1234ABCD, alignment 0

$ python3 syslog_watch.py --report
=== syslog-watch daily report ===
Messages today : 15
Alerts today   : 12

By severity:
  crit     1
  err      1
  warning  2
  notice   7
  info     3
  debug    1

By hostname:
  core-sw-01           8
  edge-rtr-01          7

Top alert rules:
  Interface up/down            4
  SSH failed login             3
  OSPF neighbor change         2
  Configuration change         2
  Critical severity catch-all  1
```

## Alert rule format

`rules.json`:

```json
{
  "rules": [
    {"name": "SSH failed login", "pattern": "Failed (password|publickey)|authentication failure|Invalid user|LOGIN_FAILED", "severity": 6},
    {"name": "Interface up/down", "pattern": "%LINK-3-UPDOWN|%LINEPROTO-5-UPDOWN", "severity": 5},
    {"name": "Critical severity catch-all", "pattern": ".*", "severity": 2}
  ]
}
```

- `pattern` — Python regex matched against the raw syslog datagram.
- `severity` — the *least severe* level that still triggers the rule: a message
  triggers when its severity number is **<=** the rule's severity
  (lower number = more severe: 0=emerg … 7=debug).
- A message can trigger several rules; each match is recorded separately.

## Pointing real devices at it

- **Cisco IOS**: `logging host <collector-ip> transport udp port 5140`
- **Linux (rsyslog)**: add `*.* @<collector-ip>:5140` to `/etc/rsyslog.conf`
  (use `@@` for TCP — note this collector is UDP-only)

## CLI reference

```
python3 syslog_watch.py [--port 5140] [--db syslog.db] [--rules rules.json]
python3 syslog_watch.py --report [--db syslog.db]
```

| Flag      | Default      | Description                              |
|-----------|--------------|------------------------------------------|
| `--port`  | `5140`       | UDP port to listen on                    |
| `--db`    | `syslog.db`  | SQLite database file                     |
| `--rules` | `rules.json` | Alert rules file                         |
| `--report`| —            | Print today's summary and exit           |

## Requirements

- Python 3.8+ (standard library only: `socketserver`, `sqlite3`, `re`, `argparse`, `json`)

## License

MIT
