#!/usr/bin/env python3
"""
syslog-watch
============
Lightweight UDP syslog collector with SQLite storage and regex-based alerting.

    # Collect syslog on UDP port 5140 (non-privileged, no root needed)
    python3 syslog_watch.py [--port 5140] [--db syslog.db] [--rules rules.json]

    # Print a daily summary and exit
    python3 syslog_watch.py --report [--db syslog.db]

Pure Python standard library. Python 3.8+.
"""

import argparse
import json
import re
import socketserver
import sqlite3
import sys
from datetime import datetime

SEVERITY_NAMES = (
    "emerg",    # 0
    "alert",    # 1
    "crit",     # 2
    "err",      # 3
    "warning",  # 4
    "notice",   # 5
    "info",     # 6
    "debug",    # 7
)

FACILITY_NAMES = {
    0: "kernel", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "logaudit", 14: "logalert", 15: "clock",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

PRI_RE = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)

RFC3164_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    timestamp   TEXT,
    hostname    TEXT,
    facility    INTEGER,
    severity    INTEGER,
    tag         TEXT,
    message     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    triggered_at TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    severity     INTEGER,
    hostname     TEXT,
    message      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered ON alerts(triggered_at);
"""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_rfc5424(rest):
    """Parse the body of an RFC 5424 message.

    Returns (timestamp, hostname, tag, message) or None if not RFC 5424.
    """
    parts = rest.split(" ", 6)
    if len(parts) < 7:
        return None
    version, ts, host, app, procid, msgid, remainder = parts
    if not version.isdigit():
        return None
    # RFC 5424 timestamps are ISO-8601 ("2026-10-07T10:30:00Z").
    if "T" not in ts and "-" not in ts:
        return None
    remainder = remainder.lstrip()
    if remainder.startswith("-"):
        remainder = remainder[1:].lstrip()
    elif remainder.startswith("["):
        # Consume structured-data blocks: [id ...][id ...] message
        i = 0
        while remainder.startswith("[", i):
            end = remainder.find("]", i)
            if end == -1:
                break
            i = end + 1
        remainder = remainder[i:].lstrip()
    tag = app if procid == "-" else "%s[%s]" % (app, procid)
    return ts, host, tag, remainder


def parse_rfc3164(rest):
    """Parse the body of an RFC 3164 message ("Mmm dd hh:mm:ss host tag: msg").

    Returns (timestamp, hostname, tag, message) or None if not RFC 3164.
    """
    match = RFC3164_RE.match(rest)
    if not match:
        return None
    timestamp = "%s %s %s" % (
        match.group("mon"), match.group("day").zfill(2), match.group("time"))
    hostname = match.group("host")
    rest_msg = match.group("rest")
    if ":" in rest_msg:
        tag, message = rest_msg.split(":", 1)
        tag, message = tag.strip(), message.strip()
    else:
        tag, message = "", rest_msg.strip()
    return timestamp, hostname, tag, message


def parse_datagram(data):
    """Parse one UDP datagram into a dict.

    Understands RFC 3164 and RFC 5424; anything else is stored raw with
    NULL facility/severity so nothing is ever lost.
    """
    raw = data.decode("utf-8", errors="replace").rstrip("\x00\r\n")
    facility = severity = None
    timestamp = None
    hostname = ""
    tag = ""
    message = raw

    match = PRI_RE.match(raw)
    if match:
        pri = int(match.group(1))
        if pri <= 191:                      # valid PRI range (0-191)
            facility, severity = divmod(pri, 8)
            rest = match.group(2)
            parsed = parse_rfc5424(rest) or parse_rfc3164(rest)
            if parsed:
                timestamp, hostname, tag, message = parsed

    return {
        "raw": raw,
        "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": timestamp,
        "hostname": hostname,
        "facility": facility,
        "severity": severity,
        "tag": tag,
        "message": message,
    }


def severity_name(severity):
    if severity is None or not 0 <= severity <= 7:
        return "unknown"
    return SEVERITY_NAMES[severity]


def facility_name(facility):
    return FACILITY_NAMES.get(facility, "unknown")


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class SyslogDB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)

    def insert_message(self, parsed):
        self.conn.execute(
            "INSERT INTO messages "
            "(received_at, timestamp, hostname, facility, severity, tag, message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (parsed["received_at"], parsed["timestamp"], parsed["hostname"],
             parsed["facility"], parsed["severity"], parsed["tag"],
             parsed["message"]),
        )
        self.conn.commit()

    def insert_alert(self, rule_name, parsed):
        self.conn.execute(
            "INSERT INTO alerts (triggered_at, rule_name, severity, hostname, message) "
            "VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), rule_name,
             parsed["severity"], parsed["hostname"], parsed["message"]),
        )
        self.conn.commit()

    def daily_summary(self):
        """Return today's message/alert statistics as dicts."""
        cur = self.conn.cursor()
        where = "date(received_at, 'localtime') = date('now', 'localtime')"
        total = cur.execute(
            "SELECT COUNT(*) FROM messages WHERE %s" % where).fetchone()[0]
        by_severity = cur.execute(
            "SELECT severity, COUNT(*) FROM messages WHERE %s "
            "GROUP BY severity ORDER BY severity" % where).fetchall()
        by_host = cur.execute(
            "SELECT hostname, COUNT(*) FROM messages WHERE %s "
            "GROUP BY hostname ORDER BY COUNT(*) DESC" % where).fetchall()
        top_rules = cur.execute(
            "SELECT rule_name, COUNT(*) FROM alerts "
            "WHERE date(triggered_at, 'localtime') = date('now', 'localtime') "
            "GROUP BY rule_name ORDER BY COUNT(*) DESC").fetchall()
        total_alerts = cur.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE date(triggered_at, 'localtime') = date('now', 'localtime')"
        ).fetchone()[0]
        return {
            "total": total,
            "by_severity": by_severity,
            "by_host": by_host,
            "top_rules": top_rules,
            "total_alerts": total_alerts,
        }

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def load_rules(path):
    """Load alert rules. Each rule: {"name", "pattern" (regex), "severity"}.

    "severity" is the least-severe level that still triggers the rule:
    a message triggers when its severity number is <= the rule's severity
    (lower number = more severe) and the regex matches the raw datagram.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print("warning: rules file %s not found, running without alert rules"
              % path, file=sys.stderr)
        return []
    except json.JSONDecodeError as exc:
        print("warning: invalid JSON in %s (%s), running without alert rules"
              % (path, exc), file=sys.stderr)
        return []

    rules = []
    for entry in data.get("rules", []):
        try:
            compiled = re.compile(entry["pattern"])
        except re.error as exc:
            print("warning: skipping rule %r: bad regex (%s)"
                  % (entry.get("name"), exc), file=sys.stderr)
            continue
        rules.append({
            "name": entry.get("name", "unnamed"),
            "pattern": compiled,
            "severity": entry.get("severity", 7),
        })
    return rules


def check_alerts(parsed, rules, db):
    """Test a parsed message against every rule; record and print matches."""
    severity = parsed["severity"]
    for rule in rules:
        if severity is None or severity > rule["severity"]:
            continue
        if not rule["pattern"].search(parsed["raw"]):
            continue
        db.insert_alert(rule["name"], parsed)
        print("ALERT [%s] %s (%s): %s" % (
            rule["name"], parsed["hostname"] or "-",
            severity_name(severity), parsed["message"]), file=sys.stderr)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class SyslogUDPServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, address, handler, db, rules):
        self.db = db
        self.rules = rules
        super().__init__(address, handler)


class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        parsed = parse_datagram(data)
        self.server.db.insert_message(parsed)
        check_alerts(parsed, self.server.rules, self.server.db)


def print_report(db):
    summary = db.daily_summary()
    print("=== syslog-watch daily report ===")
    print("Messages today : %d" % summary["total"])
    print("Alerts today   : %d" % summary["total_alerts"])
    print()
    print("By severity:")
    if summary["by_severity"]:
        for severity, count in summary["by_severity"]:
            print("  %-8s %d" % (severity_name(severity), count))
    else:
        print("  (none)")
    print()
    print("By hostname:")
    if summary["by_host"]:
        for host, count in summary["by_host"]:
            print("  %-20s %d" % (host or "-", count))
    else:
        print("  (none)")
    print()
    print("Top alert rules:")
    if summary["top_rules"]:
        for name, count in summary["top_rules"]:
            print("  %-28s %d" % (name, count))
    else:
        print("  (none)")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Lightweight UDP syslog collector with SQLite storage "
                    "and regex-based alerting.")
    parser.add_argument("--port", type=int, default=5140,
                        help="UDP port to listen on (default: 5140)")
    parser.add_argument("--db", default="syslog.db",
                        help="SQLite database file (default: syslog.db)")
    parser.add_argument("--rules", default="rules.json",
                        help="Alert rules JSON file (default: rules.json)")
    parser.add_argument("--report", action="store_true",
                        help="Print today's summary and exit")
    args = parser.parse_args(argv)

    db = SyslogDB(args.db)

    if args.report:
        print_report(db)
        db.close()
        return 0

    rules = load_rules(args.rules)
    print("syslog-watch listening on UDP port %d (%d alert rule%s loaded)"
          % (args.port, len(rules), "" if len(rules) == 1 else "s"))
    print("database: %s   (Ctrl+C to stop)" % args.db)

    server = SyslogUDPServer(("0.0.0.0", args.port), SyslogHandler, db, rules)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
