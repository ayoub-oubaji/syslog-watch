#!/usr/bin/env python3
"""
send_test_logs.py — syslog traffic simulator for syslog-watch demos.

Sends a burst of realistic Cisco-style syslog messages (interface flaps,
failed SSH logins, config changes, OSPF adjacency changes, plus some
routine informational noise) to a syslog collector.

Usage:
    python3 syslog_watch.py &          # terminal 1: start the collector
    python3 send_test_logs.py          # terminal 2: send the demo traffic
    python3 syslog_watch.py --report   # terminal 1: print the daily summary

Only the Python standard library is required. Python 3.8+.
"""

import argparse
import socket
import time

# (PRI, message). PRI = facility * 8 + severity (facility 23 = local7).
MESSAGES = [
    # --- interface flap on the core switch ---
    (187, "Oct  7 11:00:01 core-sw-01 %LINK-3-UPDOWN: "
          "Interface GigabitEthernet1/0/12, changed state to down"),
    (189, "Oct  7 11:00:04 core-sw-01 %LINEPROTO-5-UPDOWN: "
          "Line protocol on Interface GigabitEthernet1/0/12, changed state to down"),
    # --- failed SSH login attempts on the edge router ---
    (188, "Oct  7 11:00:07 edge-rtr-01 %SEC_LOGIN-4-LOGIN_FAILED: "
          "Login failed [user: admin] [Source: 203.0.113.45] "
          "[localport: 22] [Reason: Login Authentication Failed]"),
    # --- config change ---
    (189, "Oct  7 11:00:10 edge-rtr-01 %SYS-5-CONFIG_I: "
          "Configured from console by admin on vty0 (203.0.113.45)"),
    # --- OSPF adjacency drop ---
    (189, "Oct  7 11:00:13 core-sw-01 %OSPF-5-ADJCHG: Process 10, "
          "Nbr 10.255.1.2 on Vlan20 from FULL to DOWN, Neighbor Down: "
          "Dead timer expired"),
    # --- interface comes back up ---
    (189, "Oct  7 11:00:16 core-sw-01 %LINK-3-UPDOWN: "
          "Interface GigabitEthernet1/0/12, changed state to up"),
    (189, "Oct  7 11:00:19 core-sw-01 %LINEPROTO-5-UPDOWN: "
          "Line protocol on Interface GigabitEthernet1/0/12, changed state to up"),
    # --- more failed logins (brute-force pattern) ---
    (188, "Oct  7 11:00:22 edge-rtr-01 %SEC_LOGIN-4-LOGIN_FAILED: "
          "Login failed [user: root] [Source: 198.51.100.23] "
          "[localport: 22] [Reason: Login Authentication Failed]"),
    # --- another config change ---
    (189, "Oct  7 11:00:25 edge-rtr-01 %SYS-5-CONFIG_I: "
          "Configured from console by netadmin on vty1 (198.51.100.7)"),
    # --- OSPF adjacency recovers ---
    (189, "Oct  7 11:00:28 core-sw-01 %OSPF-5-ADJCHG: Process 10, "
          "Nbr 10.255.1.2 on Vlan20 from DOWN to FULL, Loading Done"),
    # --- RFC 5424 sshd message (Linux server) ---
    (38, "1 2026-10-07T11:00:31Z edge-rtr-01 sshd 4821 ID47 - "
         "Failed password for invalid user test from 203.0.113.99 "
         "port 51234 ssh2"),
    # --- critical: memory allocation failure ---
    (10, "Oct  7 11:00:34 core-sw-01 %SYS-2-MALLOCFAIL: "
         "Memory allocation of 1024 bytes failed from 0x1234ABCD, alignment 0"),
    # --- routine informational noise (no alerts expected) ---
    (190, "Oct  7 11:00:37 edge-rtr-01 %SYS-6-LOGGINGHOST_STARTSTOP: "
          "Logging to host 192.168.100.10 started - CLI initiated"),
    (191, "Oct  7 11:00:40 core-sw-01 %CDP-4-NATIVE_VLAN_MISMATCH: "
          "Native VLAN mismatch discovered on GigabitEthernet1/0/5 (1), "
          "with GigabitEthernet0/1 (20)"),
    (190, "Oct  7 11:00:43 edge-rtr-01 %SYS-6-CLOCKUPDATE: "
          "System clock has been updated from 10:59:59 UTC to 11:00:43 UTC"),
]


def main():
    parser = argparse.ArgumentParser(
        description="Send demo syslog traffic to a syslog-watch collector.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Collector address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5140,
                        help="Collector UDP port (default: 5140)")
    parser.add_argument("--delay", type=float, default=0.15,
                        help="Seconds between messages (default: 0.15)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for pri, text in MESSAGES:
        datagram = "<%d>%s" % (pri, text)
        sock.sendto(datagram.encode("utf-8"), (args.host, args.port))
        print("sent: %s" % text[:80])
        time.sleep(args.delay)
    sock.close()
    print("done: %d messages sent to %s:%d" % (len(MESSAGES), args.host, args.port))


if __name__ == "__main__":
    main()
