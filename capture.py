#!/usr/bin/env python3
"""
Network traffic capture + live feed for the 3D Traffic Dashboard.

- Sniffs packets via tcpdump (needs sudo) OR generates simulated traffic (--simulate)
- Classifies each packet by service (HTTPS, HTTP, DNS, SSH, Streaming, Email, ICMP, Other)
- Logs packets to traffic_log.jsonl
- Streams events to the dashboard via Server-Sent Events on http://localhost:8765/events
- Also serves dashboard.html at http://localhost:8765/

Usage:
    sudo python3 capture.py                 # real capture, default interface
    sudo python3 capture.py -i en0          # specific interface
    python3 capture.py --simulate           # fake traffic, no sudo needed

Stdlib only — no pip installs required.
"""

import argparse
import json
import os
import queue
import random
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, "traffic_log.jsonl")
LOG_MAX_BYTES = 50 * 1024 * 1024  # rotate at 50 MB
PORT = 8765
BROADCAST_MAX_PER_SEC = 120  # cap per-packet events sent to clients; stats stay exact

CATEGORIES = ["HTTPS", "HTTP", "DNS", "SSH", "Streaming", "Email", "ICMP", "Other"]

EMAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
STREAMING_UDP = {443, 1935, 554, 3478, 3479, 3480, 3481}  # QUIC, RTMP, RTSP, STUN/WebRTC


def classify(proto, sport, dport):
    ports = {sport, dport}
    if proto == "icmp":
        return "ICMP"
    if proto == "udp":
        if ports & {53, 5353}:
            return "DNS"
        if ports & STREAMING_UDP:
            return "Streaming"
        return "Other"
    # tcp
    if 443 in ports:
        return "HTTPS"
    if ports & {80, 8080}:
        return "HTTP"
    if 53 in ports:
        return "DNS"
    if 22 in ports:
        return "SSH"
    if ports & EMAIL_PORTS:
        return "Email"
    return "Other"


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


_RDNS_CACHE = {}
_RDNS_LOCK = threading.Lock()


def reverse_dns(ip):
    """Cached PTR lookup. Returns '' for private IPs and failures (cached too)."""
    with _RDNS_LOCK:
        if ip in _RDNS_CACHE:
            return _RDNS_CACHE[ip]
    if is_private(ip):
        name = ""
    else:
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            name = ""
    with _RDNS_LOCK:
        if len(_RDNS_CACHE) > 5000:
            _RDNS_CACHE.clear()
        _RDNS_CACHE[ip] = name
    return name


def is_private(ip):
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip)
        or ip.startswith("127.")
    )


# ---------------------------------------------------------------- hub / state

class Hub:
    """Fan-out of events to SSE clients + rolling stats + JSONL logging."""

    def __init__(self, log_enabled=True):
        self.clients = set()
        self.lock = threading.Lock()
        self.counts = {c: {"in": 0, "out": 0, "bytes": 0} for c in CATEGORIES}
        self.total_pkts = 0
        self.total_bytes = 0
        self.window = []  # (ts, bytes, dir) for rate calc
        self.sent_this_sec = 0
        self.sec_mark = int(time.time())
        self.log_enabled = log_enabled
        self.log_file = open(LOG_PATH, "a", buffering=1) if log_enabled else None

    def add_client(self):
        q = queue.Queue(maxsize=500)
        with self.lock:
            self.clients.add(q)
        return q

    def drop_client(self, q):
        with self.lock:
            self.clients.discard(q)

    def _push(self, msg):
        with self.lock:
            dead = []
            for q in self.clients:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.clients.discard(q)

    def packet(self, evt):
        now = time.time()
        cat, d, ln = evt["cat"], evt["dir"], evt["len"]
        with self.lock:
            self.counts[cat][d] += 1
            self.counts[cat]["bytes"] += ln
            self.total_pkts += 1
            self.total_bytes += ln
            self.window.append((now, ln, d))

        if self.log_file:
            try:
                self.log_file.write(json.dumps(evt, separators=(",", ":")) + "\n")
                if self.log_file.tell() > LOG_MAX_BYTES:
                    self.log_file.close()
                    os.replace(LOG_PATH, LOG_PATH + ".1")
                    self.log_file = open(LOG_PATH, "a", buffering=1)
            except OSError:
                pass

        # rate-limit per-packet broadcasts (stats stay exact)
        sec = int(now)
        if sec != self.sec_mark:
            self.sec_mark, self.sent_this_sec = sec, 0
        if self.sent_this_sec < BROADCAST_MAX_PER_SEC:
            self.sent_this_sec += 1
            self._push(json.dumps({"type": "pkt", **evt}, separators=(",", ":")))

    def stats_loop(self):
        while True:
            time.sleep(1.0)
            now = time.time()
            with self.lock:
                self.window = [w for w in self.window if now - w[0] <= 5.0]
                win = list(self.window)
                snapshot = {
                    "type": "stats",
                    "ts": round(now, 3),
                    "totalPkts": self.total_pkts,
                    "totalBytes": self.total_bytes,
                    "pps": round(len(win) / 5.0, 1),
                    "bps": round(sum(w[1] for w in win) / 5.0),
                    "inBps": round(sum(w[1] for w in win if w[2] == "in") / 5.0),
                    "outBps": round(sum(w[1] for w in win if w[2] == "out") / 5.0),
                    "cats": self.counts,
                }
            self._push(json.dumps(snapshot, separators=(",", ":")))


# ---------------------------------------------------------------- tcpdump

TCPDUMP_RE = re.compile(
    r"^(?P<ts>\d+\.\d+) IP6? (?P<src>[\da-fA-F:.]+?)(?:\.(?P<sport>\d+))? > "
    r"(?P<dst>[\da-fA-F:.]+?)(?:\.(?P<dport>\d+))?: (?P<rest>.*)$"
)
LEN_RE = re.compile(r"length (\d+)")


def run_tcpdump(hub, iface):
    me = local_ip()
    cmd = ["tcpdump", "-nl", "-tt", "-q"]
    if iface:
        cmd += ["-i", iface]
    print(f"[capture] starting: {' '.join(cmd)}   (local IP: {me})")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
    except FileNotFoundError:
        sys.exit("tcpdump not found. Install it or use --simulate.")

    def watch_err():
        for line in proc.stderr:
            line = line.strip()
            if line and "packets" not in line:
                print(f"[tcpdump] {line}")

    threading.Thread(target=watch_err, daemon=True).start()

    for line in proc.stdout:
        m = TCPDUMP_RE.match(line)
        if not m:
            continue
        rest = m.group("rest")
        lm = LEN_RE.search(rest)
        ln = int(lm.group(1)) if lm else 64
        rl = rest.lower()
        if "udp" in rl:
            proto = "udp"
        elif "icmp" in rl:
            proto = "icmp"
        else:
            proto = "tcp"
        src, dst = m.group("src"), m.group("dst")
        sport = int(m.group("sport") or 0)
        dport = int(m.group("dport") or 0)
        if proto == "icmp":  # no ports: regex grabbed the last IP octet — restore it
            if m.group("sport"):
                src, sport = f"{src}.{m.group('sport')}", 0
            if m.group("dport"):
                dst, dport = f"{dst}.{m.group('dport')}", 0
        if src == me:
            d = "out"
        elif dst == me:
            d = "in"
        else:
            d = "out" if is_private(src) else "in"
        hub.packet(
            {
                "ts": round(float(m.group("ts")), 3),
                "dir": d,
                "cat": classify(proto, sport, dport),
                "proto": proto,
                "len": max(ln, 40),
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
            }
        )

    code = proc.wait()
    sys.exit(f"tcpdump exited (code {code}). Did you run with sudo?")


# ---------------------------------------------------------------- simulator

SIM_PROFILES = [
    # (cat, proto, dport, weight, len_range)
    ("HTTPS", "tcp", 443, 45, (60, 1500)),
    ("Streaming", "udp", 443, 20, (400, 1500)),
    ("DNS", "udp", 53, 12, (60, 300)),
    ("HTTP", "tcp", 80, 6, (60, 1500)),
    ("SSH", "tcp", 22, 5, (60, 500)),
    ("Email", "tcp", 993, 4, (80, 1200)),
    ("ICMP", "icmp", 0, 3, (64, 120)),
    ("Other", "tcp", 8443, 5, (60, 1500)),
]


def run_simulator(hub):
    print("[capture] SIMULATION mode — generating fake traffic")
    me = "192.168.1.10"
    weights = [p[3] for p in SIM_PROFILES]
    while True:
        cat, proto, dport, _, lr = random.choices(SIM_PROFILES, weights=weights)[0]
        d = random.choices(["in", "out"], weights=[60, 40])[0]
        remote = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        sport = random.randint(49152, 65535)
        evt = {
            "ts": round(time.time(), 3),
            "dir": d,
            "cat": cat,
            "proto": proto,
            "len": random.randint(*lr),
            "src": remote if d == "in" else me,
            "dst": me if d == "in" else remote,
            "sport": dport if d == "in" else sport,
            "dport": sport if d == "in" else dport,
        }
        hub.packet(evt)
        # bursty: occasional rapid-fire
        time.sleep(random.choice([0.002] * 2 + [0.02] * 5 + [0.15]))


# ---------------------------------------------------------------- HTTP / SSE

def make_handler(hub):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache")

        def do_GET(self):
            if self.path == "/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self._cors()
                self.end_headers()
                q = hub.add_client()
                try:
                    while True:
                        try:
                            msg = q.get(timeout=15)
                            self.wfile.write(f"data: {msg}\n\n".encode())
                        except queue.Empty:
                            self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    hub.drop_client(q)
            elif self.path.startswith("/resolve"):
                ip = parse_qs(urlparse(self.path).query).get("ip", [""])[0]
                body = json.dumps({"ip": ip, "name": reverse_dns(ip) if ip else ""}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._cors()
                self.end_headers()
                self.wfile.write(body)
            elif self.path in ("/", "/dashboard.html"):
                try:
                    with open(os.path.join(HERE, "dashboard.html"), "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self._cors()
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    self.send_error(404, "dashboard.html not found")
            else:
                self.send_error(404)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Traffic capture + live feed")
    ap.add_argument("-i", "--iface", help="interface to sniff (default: tcpdump default)")
    ap.add_argument("--simulate", action="store_true", help="generate fake traffic (no sudo)")
    ap.add_argument("--no-log", action="store_true", help="disable JSONL logging")
    ap.add_argument("-p", "--port", type=int, default=PORT)
    args = ap.parse_args()

    hub = Hub(log_enabled=not args.no_log)
    threading.Thread(target=hub.stats_loop, daemon=True).start()

    if args.simulate:
        threading.Thread(target=run_simulator, args=(hub,), daemon=True).start()
    else:
        threading.Thread(target=run_tcpdump, args=(hub, args.iface), daemon=True).start()

    class Server(ThreadingHTTPServer):
        daemon_threads = True  # SSE handler threads must not block exit

    server = Server(("127.0.0.1", args.port), make_handler(hub))
    print(f"[server] dashboard:  http://localhost:{args.port}/")
    print(f"[server] event feed: http://localhost:{args.port}/events")
    if not args.no_log:
        print(f"[log]    {LOG_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] stopped")
        os._exit(0)  # don't wait on tcpdump/SSE threads


if __name__ == "__main__":
    main()
