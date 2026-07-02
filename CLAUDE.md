# CLAUDE.md — Traffic Monitor

3D network traffic dashboard: a two-way freeway where each packet is a vehicle. Inbound traffic drives the left roadway (toward viewer, +z), outbound the right (−z). Lane, color, and vehicle model indicate traffic type.

## Files

- `capture.py` — sniffer + classifier + logger + server. Pure Python stdlib, no pip deps. Parses `tcpdump` output via regex, classifies by port/protocol, attributes packets to apps via `lsof`, logs every packet to `traffic_log.jsonl` (rotated at 50 MB), serves `dashboard.html` at `/`, an SSE feed at `/events`, and cached reverse DNS at `/resolve?ip=` on port 8765. Also replays logs (`--replay`).
- `dashboard.html` — single-file Three.js (r128 from cdnjs) visualization. No build step.
- `traffic_log.jsonl` — runtime packet log. One JSON object per packet: `{ts, dir, cat, proto, len, src, dst, sport, dport, app}` (`app` empty when unknown; absent in pre-attribution logs).
- `screenshot.png` — dashboard capture referenced by README.md (user saves it there manually; pasted chat images aren't files).

## Run

```bash
sudo python3 capture.py            # real capture → open http://localhost:8765/
sudo python3 capture.py -i en0     # pin interface (fixes silent capture on macOS)
python3 capture.py --simulate      # fake traffic, no sudo
python3 capture.py --replay traffic_log.jsonl --speed 10   # replay a log, no sudo
```

`dashboard.html` also works opened as a file — it targets `localhost:8765/events` and auto-falls back to built-in simulation (amber status dot) if no feed responds within 2.5 s.

## Architecture decisions

- **SSE over WebSocket**: keeps capture.py stdlib-only (ThreadingHTTPServer + `text/event-stream`), with CORS `*` so file:// works.
- **Sampled events, exact stats**: per-packet `pkt` events are capped at 120/s (`BROADCAST_MAX_PER_SEC`) so the browser never drowns; a `stats` event every 1 s carries exact totals, pps, and in/out B/s over a 5 s window. The animation is illustrative; HUD numbers are true.
- **Direction**: src == local IP → out, dst == local IP → in; fallback on RFC1918 check. Local IP found via UDP-connect to 8.8.8.8.
- **tcpdump parsing gotcha**: ICMP lines have no port, so `TCPDUMP_RE` greedily captures the last IP octet as a port — run_tcpdump rejoins it when proto == icmp. Don't remove that fixup.
- **`sudo: ioctl(SIOCIFCREATE)` warning** is harmless macOS/libpcap noise; documented in README troubleshooting.
- **Clean shutdown**: never call `server.shutdown()` from a signal handler in the main thread — it deadlocks (waits for `serve_forever()`, which is stuck in the handler). Instead: `daemon_threads = True` on the server class + catch KeyboardInterrupt + `os._exit(0)`. SSE handler threads block forever by design, so a graceful join is impossible.
- **Top talkers**: Hub aggregates exact per-remote-IP `{pkts, bytes}` in `self.talkers` (remote = src when inbound, dst when outbound; bounded at 4000 entries, pruned to heaviest 1000). The 1 s `stats` event carries `top` (top 10 by bytes); dashboard renders it below the legend and resolves names via the dnsCache. Sim mode aggregates client-side in `localTalkers`.
- **Process attribution**: real capture starts `lsof_loop()` — polls `lsof -nP -i -F cnP` every 3 s into `_PORT_APPS` `{(proto, local_port): app}`; `port_app()` tags each event with `"app"` (local port = sport when out, dport when in). Simulator hardcodes fake app names per profile; replay carries whatever the log has. Dashboard shows it in the inspector tooltip.
- **Replay**: `--replay PATH [--speed N]` feeds a JSONL log through `hub.packet()`, sleeping per-line ts deltas (clamped to 5 s) ÷ speed, rewriting `ts` to now so rolling stats work. Logging is forced off in replay mode (would append the log to itself). Mutually exclusive with `--simulate`.
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
- Origin labels: each vehicle has a `THREE.Sprite` above it showing the remote host (IP, swapped to domain when `resolveIp()` lands, guarded by `v.meta === p`). Textures come from `labelAsset()` — an LRU `Map` capped at 300 (evicted textures disposed); IPs repeat so hit rate is high. Visible only when camera is within `LABEL_DIST` (95), opacity fades over `LABEL_FADE`.
- Legend filter: clicking a `.cat-row` toggles the category in `hiddenCats` (spawns skipped, active vehicles recycled immediately, row dimmed via `.off`). Visual only — counts/stats stay exact.
- Throughput sparkline: `#spark` panel canvas, `sparkHist` ring of 180 one-second `{i, o}` B/s samples fed by `pushSpark()` from server stats (live) or the sim ticker; hover shows a crosshair + values. Series colors are the HUD's in/out entity colors (`#4ade80`/`#38bdf8`) — brighter than the dataviz dark-band guideline, kept deliberately for entity consistency; CVD/contrast validated.

## Testing (sandbox has no sudo — real capture must be tested on the Mac)

```bash
python3 -m py_compile capture.py
python3 capture.py --simulate --no-log -p 8802 &   # then curl the endpoints
curl -s http://localhost:8802/events | head        # expect pkt + stats JSON, "app" on pkts
python3 capture.py --replay some.jsonl --speed 10 -p 8803 &   # replay smoke test
```

JS syntax check (the Mac has no Node): extract the `<script>` block, wrap it in `void function(){…};` so nothing executes, and run `osascript -l JavaScript file.js` — JavaScriptCore reports syntax errors.

`lsof_loop()` can be exercised without sudo (sees only your own processes — enough to test parsing); root sees all. Real-capture attribution must be tested on the Mac.

Caution: `pkill -f capture.py` inside a sandbox bash call kills the shell itself (the `bash -c` cmdline matches). Kill by port instead: `kill $(lsof -ti :8802)`.
