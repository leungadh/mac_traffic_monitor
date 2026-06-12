# CLAUDE.md — Traffic Monitor

3D network traffic dashboard: a two-way freeway where each packet is a vehicle. Inbound traffic drives the left roadway (toward viewer, +z), outbound the right (−z). Lane, color, and vehicle model indicate traffic type.

## Files

- `capture.py` — sniffer + classifier + logger + server. Pure Python stdlib, no pip deps. Parses `tcpdump` output via regex, classifies by port/protocol, logs every packet to `traffic_log.jsonl` (rotated at 50 MB), serves `dashboard.html` at `/`, an SSE feed at `/events`, and cached reverse DNS at `/resolve?ip=` on port 8765.
- `dashboard.html` — single-file Three.js (r128 from cdnjs) visualization. No build step.
- `traffic_log.jsonl` — runtime packet log. One JSON object per packet: `{ts, dir, cat, proto, len, src, dst, sport, dport}`.
- `screenshot.png` — dashboard capture referenced by README.md (user saves it there manually; pasted chat images aren't files).

## Run

```bash
sudo python3 capture.py            # real capture → open http://localhost:8765/
sudo python3 capture.py -i en0     # pin interface (fixes silent capture on macOS)
python3 capture.py --simulate      # fake traffic, no sudo
```

`dashboard.html` also works opened as a file — it targets `localhost:8765/events` and auto-falls back to built-in simulation (amber status dot) if no feed responds within 2.5 s.

## Architecture decisions

- **SSE over WebSocket**: keeps capture.py stdlib-only (ThreadingHTTPServer + `text/event-stream`), with CORS `*` so file:// works.
- **Sampled events, exact stats**: per-packet `pkt` events are capped at 120/s (`BROADCAST_MAX_PER_SEC`) so the browser never drowns; a `stats` event every 1 s carries exact totals, pps, and in/out B/s over a 5 s window. The animation is illustrative; HUD numbers are true.
- **Direction**: src == local IP → out, dst == local IP → in; fallback on RFC1918 check. Local IP found via UDP-connect to 8.8.8.8.
- **tcpdump parsing gotcha**: ICMP lines have no port, so `TCPDUMP_RE` greedily captures the last IP octet as a port — run_tcpdump rejoins it when proto == icmp. Don't remove that fixup.
- **`sudo: ioctl(SIOCIFCREATE)` warning** is harmless macOS/libpcap noise; documented in README troubleshooting.
- **Clean shutdown**: never call `server.shutdown()` from a signal handler in the main thread — it deadlocks (waits for `serve_forever()`, which is stuck in the handler). Instead: `daemon_threads = True` on the server class + catch KeyboardInterrupt + `os._exit(0)`. SSE handler threads block forever by design, so a graceful join is impossible.
- **Reverse DNS**: `/resolve?ip=` endpoint does a cached PTR lookup (`reverse_dns()`; failures and private IPs cached as `""`, cache cleared past 5000 entries). Tooltip shows the IP instantly, then swaps in the domain async (`resolveIp()` + `pickToken` guard against stale updates). PTR can block a few seconds per new IP but each request gets its own thread (ThreadingHTTPServer). Note: sandbox blocks ALL raw DNS — `/resolve` always returns `""` there; test on the Mac. Many CDN IPs legitimately have no PTR record.

## Traffic categories (order matters — it's the lane order, index = `CAT_INDEX`)

HTTPS (green, sedan) · HTTP (amber, pickup) · DNS (cyan, motorcycle) · SSH (violet, armored truck) · Streaming (pink, semi — trailer length scales with packet size) · Email (blue, mail van) · ICMP (red, emergency car w/ flashing beacon) · Other (gray, compact).

The `CATS` array in dashboard.html and `CATEGORIES`/`classify()` in capture.py must stay in sync by name. Streaming = UDP 443 (QUIC), RTMP, RTSP, STUN/WebRTC ports.

## Dashboard internals

- Vehicles are box-part groups built facing +z; outbound spawns rotate `y = π`. Per-category pools (`pools[ci]`), global cap `POOL_SIZE = 360`, recycled past road end.
- Speed by vehicle class (`SPEEDS`, indexed like CATS); packet size stretches the body (or the semi's trailer).
- Spawn queue capped at `MAX_QUEUE = 140`, ≤ 5 spawns/frame.
- Click-to-inspect: raycast on pointerup when movement < 6 px and < 450 ms (else it's an orbit drag); each mesh carries `userData.v` pointing to its vehicle, which holds `meta` (the packet).
- Gantry billboard: CanvasTexture updated each second from `lastStats` (fed by server stats when live, local 5 s window in sim mode).
- Camera: manual spherical orbit (drag) + wheel zoom; no OrbitControls dependency.

## Testing (sandbox has no sudo — real capture must be tested on the Mac)

```bash
python3 -m py_compile capture.py
python3 capture.py --simulate --no-log -p 8802 &   # then curl the endpoints
curl -s http://localhost:8802/events | head        # expect pkt + stats JSON
# JS check: extract <script> blocks → node --check
```

Caution: `pkill -f capture.py` inside a sandbox bash call kills the shell itself (the `bash -c` cmdline matches). Kill by port instead: `kill $(lsof -ti :8802)`.
