#!/usr/bin/env python3
"""
Kali Terminal Server v5
- IP logging, live session view, keyword alerts
- PTY mode on Linux / pipe fallback on Windows
- PostgreSQL via pg8000, aiohttp HTTP+WS
"""
import asyncio, json, os, sys, socket, shutil, uuid, secrets, time, hmac, hashlib
from datetime import datetime
from aiohttp import web
import aiohttp

try:
    import pg8000.native as pg8k
    HAS_PG = True
except ImportError:
    pg8k = None; HAS_PG = False

TOKEN          = os.environ.get("KALI_TOKEN",      "kali2024")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "changeme")
PORT           = int(os.environ.get("PORT", 8765))
DB             = os.environ.get("DATABASE_URL")

# ── Auth state ────────────────────────────────────────────────────────────────
COOKIE_NAME    = "kt_auth"
COOKIE_SECRET  = secrets.token_hex(32)          # random per-process signing key
dash_sessions: dict = {}                         # token -> expiry (unix ts)
login_attempts: dict = {}                        # ip    -> (count, window_end)

USE_PTY = sys.platform != "win32"
if USE_PTY:
    import pty, fcntl, termios, struct

# Commands that trigger an alert
ALERT_KEYWORDS = [
    "rm -rf", "rm -fr",
    "/etc/shadow", "/etc/passwd",
    "nc -e", "netcat -e",
    "bash -i", "sh -i",
    "chmod 777", "chmod 4777",
    "mkfs", "dd if=",
    "> /dev/sd",
    "python -c", "python3 -c",
    "perl -e", "ruby -e",
    "base64 -d",
    ":(){:|:&};:",
]

db_ok    = False
mem_history: dict = {}
mem_stats:   dict = {}
active_ws:   dict = {}
watchers:    dict = {}

# ── Auth helpers ───────────────────────────────────────────────────────────────

def _sign(token: str) -> str:
    """HMAC-sign a token so cookies can't be forged."""
    return hmac.new(COOKIE_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()

def make_session() -> str:
    token = secrets.token_hex(32)
    dash_sessions[token] = time.time() + 86400 * 7   # 7-day expiry
    return token

def check_session(request) -> bool:
    raw = request.cookies.get(COOKIE_NAME, "")
    if not raw or "." not in raw:
        return False
    token, sig = raw.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(token)):
        return False
    expiry = dash_sessions.get(token, 0)
    return time.time() < expiry

def check_rate_limit(ip: str) -> bool:
    """Allow max 5 login attempts per 60 s per IP."""
    now = time.time()
    count, window = login_attempts.get(ip, (0, now + 60))
    if now > window:
        login_attempts[ip] = (1, now + 60)
        return True
    if count >= 5:
        return False
    login_attempts[ip] = (count + 1, window)
    return True

# Routes that skip auth (terminal WS + login)
_PUBLIC = {"/login", "/ws", "/ws/", "/terminal"}

@web.middleware
async def auth_middleware(request, handler):
    path = request.path
    if path in _PUBLIC or path.startswith("/api/watch/"):
        return await handler(request)
    if not check_session(request):
        if path.startswith("/api/"):
            return web.Response(status=401, text="Unauthorized")
        raise web.HTTPFound("/login")
    return await handler(request)

# ── DB ─────────────────────────────────────────────────────────────────────────

def _conn():
    import urllib.parse as up
    u = up.urlparse(DB)
    return pg8k.Connection(host=u.hostname, port=u.port or 5432,
        database=u.path.lstrip("/"), user=u.username,
        password=u.password, ssl_context=True)

async def init_db():
    global db_ok
    if not DB or not HAS_PG:
        print("  [!] No DB — memory only", flush=True); return
    try:
        def _f():
            c = _conn()
            c.run("SELECT 1")
            # Migrate: add ip_address to sessions
            try: c.run("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address TEXT")
            except Exception: pass
            # Migrate: alerts table
            c.run("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id           SERIAL PRIMARY KEY,
                    session_id   TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
                    command      TEXT,
                    keyword      TEXT,
                    triggered_at TIMESTAMPTZ DEFAULT NOW(),
                    acknowledged BOOLEAN DEFAULT FALSE
                )
            """)
            c.close()
        await asyncio.to_thread(_f)
        db_ok = True
        print("  [+] PostgreSQL connected", flush=True)
    except Exception as e:
        print(f"  [!] DB error: {e}", flush=True)

async def db_start(sid, shell, ip):
    if not db_ok: return
    def _f():
        c = _conn()
        c.run("INSERT INTO sessions(session_id,shell,ip_address) VALUES(:s,:h,:i) ON CONFLICT DO NOTHING",
              s=sid, h=shell, i=ip)
        c.close()
    try: await asyncio.to_thread(_f)
    except Exception: pass

async def db_end(sid, count):
    if not db_ok: return
    def _f():
        c = _conn()
        c.run("UPDATE sessions SET disconnected_at=NOW(),command_count=:n WHERE session_id=:s", n=count, s=sid)
        c.close()
    try: await asyncio.to_thread(_f)
    except Exception: pass

async def db_cmd(sid, cmd):
    if not db_ok: return
    def _f():
        c = _conn()
        c.run("INSERT INTO commands(session_id,command) VALUES(:s,:c)", s=sid, c=cmd)
        c.run("UPDATE sessions SET command_count=command_count+1 WHERE session_id=:s", s=sid)
        c.close()
    try: await asyncio.to_thread(_f)
    except Exception: pass

async def db_alert(sid, cmd, keyword):
    if not db_ok: return
    def _f():
        c = _conn()
        c.run("INSERT INTO alerts(session_id,command,keyword) VALUES(:s,:c,:k)", s=sid, c=cmd, k=keyword)
        c.close()
    try: await asyncio.to_thread(_f)
    except Exception: pass

async def db_hist(sid):
    if not db_ok: return []
    def _f():
        c = _conn()
        rows = c.run("SELECT command,executed_at FROM commands WHERE session_id=:s ORDER BY executed_at DESC LIMIT 100", s=sid)
        c.close()
        return [{"cmd": r[0], "ts": r[1].isoformat()} for r in rows]
    try: return await asyncio.to_thread(_f)
    except Exception: return []

def db_dashboard_data():
    if not db_ok:
        return {"stats":{"total_sessions":0,"active_sessions":0,"total_commands":0,"sessions_today":0,"alerts":0},
                "sessions":[],"commands":[],"alerts":[]}
    c = _conn()
    try:
        s = c.run("""SELECT
            (SELECT COUNT(*) FROM sessions),
            (SELECT COUNT(*) FROM sessions WHERE disconnected_at IS NULL),
            (SELECT COUNT(*) FROM commands),
            (SELECT COUNT(*) FROM sessions WHERE connected_at > NOW()-INTERVAL '24 hours'),
            (SELECT COUNT(*) FROM alerts WHERE acknowledged=FALSE)
        """)[0]
        stats = {"total_sessions":int(s[0]),"active_sessions":int(s[1]),
                 "total_commands":int(s[2]),"sessions_today":int(s[3]),"alerts":int(s[4])}

        sess = [{"session_id":r[0],
                 "connected_at":r[1].isoformat() if r[1] else None,
                 "disconnected_at":r[2].isoformat() if r[2] else None,
                 "command_count":r[3],"shell":r[4],"ip":r[5]}
                for r in c.run("SELECT session_id,connected_at,disconnected_at,command_count,shell,ip_address FROM sessions ORDER BY connected_at DESC LIMIT 50")]

        cmds = [{"command":r[0],"executed_at":r[1].isoformat() if r[1] else None,"session_id":r[2]}
                for r in c.run("SELECT command,executed_at,session_id FROM commands ORDER BY executed_at DESC LIMIT 100")]

        alerts = [{"id":r[0],"session_id":r[1],"command":r[2],"keyword":r[3],
                   "triggered_at":r[4].isoformat() if r[4] else None}
                  for r in c.run("SELECT id,session_id,command,keyword,triggered_at FROM alerts WHERE acknowledged=FALSE ORDER BY triggered_at DESC LIMIT 50")]

        return {"stats":stats,"sessions":sess,"commands":cmds,"alerts":alerts}
    finally: c.close()

async def db_ack_alerts():
    if not db_ok: return
    def _f():
        c = _conn(); c.run("UPDATE alerts SET acknowledged=TRUE"); c.close()
    try: await asyncio.to_thread(_f)
    except Exception: pass

# ── PTY helpers ────────────────────────────────────────────────────────────────

def get_shell():
    if sys.platform != "win32": return ["/bin/bash","-i"]
    if shutil.which("wsl"):     return ["wsl.exe","bash","-i"]
    if shutil.which("bash"):    return ["bash","-i"]
    return ["powershell.exe","-NoLogo","-NoExit"]

def get_server_ip():
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close(); return ip
    except: return "localhost"

def resize_pty(fd,rows,cols):
    try: fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack("HHHH",rows,cols,0,0))
    except: pass

def check_keywords(cmd):
    low = cmd.lower()
    for kw in ALERT_KEYWORDS:
        if kw.lower() in low:
            return kw
    return None

async def broadcast(sid, text):
    """Send output to all live-view watchers."""
    for w in list(watchers.get(sid, [])):
        try: await w.send_str(text)
        except Exception: pass

async def track(sid, text):
    buf = mem_stats[sid].get("_buf","")
    for ch in text:
        if ch in ("\r","\n"):
            cmd = buf.strip()
            if cmd:
                mem_history[sid].append({"cmd":cmd,"ts":datetime.now().isoformat()})
                mem_stats[sid]["command_count"] += 1
                await db_cmd(sid, cmd)
                kw = check_keywords(cmd)
                if kw:
                    await db_alert(sid, cmd, kw)
                    # Notify all watchers with a red banner
                    banner = f"\r\n\x1b[41;97m ⚠ ALERT: matched keyword [{kw}] \x1b[0m\r\n"
                    await broadcast(sid, banner)
            buf = ""
        elif ch == "\x7f": buf = buf[:-1]
        else: buf += ch
    mem_stats[sid]["_buf"] = buf

# ── WebSocket terminal ─────────────────────────────────────────────────────────

async def ws_handler(request):
    token = request.rel_url.query.get("token","")
    if TOKEN != "off" and token != TOKEN:
        return web.Response(status=401, text="Unauthorized")

    # Extract real client IP (Railway adds X-Forwarded-For)
    ip = request.headers.get("X-Forwarded-For", request.remote or "unknown").split(",")[0].strip()

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    sid   = str(uuid.uuid4())[:8]
    shell = get_shell()
    mem_history[sid] = []
    mem_stats[sid]   = {"command_count":0,"connected_at":datetime.now().isoformat(),"_buf":""}
    active_ws[sid]   = ws
    watchers[sid]    = []

    await db_start(sid, " ".join(shell), ip)
    await ws.send_json({"type":"session","session_id":sid,"pty":USE_PTY})

    try:
        if USE_PTY: await _pty_session(ws, sid, shell)
        else:       await _pipe_session(ws, sid, shell)
    finally:
        active_ws.pop(sid, None)
        # Close any live-view watchers
        for w in list(watchers.pop(sid, [])):
            try: await w.close()
            except Exception: pass
        await db_end(sid, mem_stats.get(sid,{}).get("command_count",0))
        mem_history.pop(sid, None)
        mem_stats.pop(sid, None)

    return ws

async def _pty_session(ws, sid, shell):
    master,slave = pty.openpty(); resize_pty(master,40,120)
    import subprocess
    proc = subprocess.Popen(shell, stdin=slave, stdout=slave, stderr=slave,
        preexec_fn=os.setsid, close_fds=True,
        env={**os.environ,"TERM":"xterm-256color","HOME":"/root","USER":"root",
             "LANG":"en_US.UTF-8","PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
    os.close(slave)
    loop  = asyncio.get_event_loop()
    queue = asyncio.Queue()
    def _read():
        try: queue.put_nowait(os.read(master,4096))
        except OSError: loop.remove_reader(master)
    loop.add_reader(master,_read)

    async def pump():
        try:
            while True:
                d = await queue.get()
                text = d.decode("utf-8",errors="replace")
                await ws.send_str(text)
                await broadcast(sid, text)  # live view
        except Exception: pass
    asyncio.ensure_future(pump())

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            data = msg.data
            if data.startswith("{"):
                try:
                    obj = json.loads(data); t = obj.get("type","")
                    if t=="resize": resize_pty(master,int(obj["rows"]),int(obj["cols"])); continue
                    if t=="history": await ws.send_json({"type":"history","history":await db_hist(sid) or mem_history.get(sid,[])}); continue
                    if t=="stats": st=mem_stats.get(sid,{}); await ws.send_json({"type":"stats","command_count":st.get("command_count",0),"session_id":sid}); continue
                except Exception: pass
            try: await track(sid,data); os.write(master,data.encode())
            except Exception: break
        elif msg.type in (aiohttp.WSMsgType.CLOSE,aiohttp.WSMsgType.ERROR): break

    loop.remove_reader(master)
    try: proc.kill()
    except Exception: pass
    try: os.close(master)
    except Exception: pass

async def _pipe_session(ws, sid, shell):
    proc = await asyncio.create_subprocess_exec(*shell,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT, env={**os.environ,"TERM":"xterm-256color"})

    async def pump():
        try:
            while True:
                d = await proc.stdout.read(4096)
                if not d: break
                text = d.decode("utf-8",errors="replace")
                await ws.send_str(text)
                await broadcast(sid, text)
        except Exception: pass
    asyncio.ensure_future(pump())

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            data = msg.data
            if data.startswith("{"):
                try:
                    obj = json.loads(data); t = obj.get("type","")
                    if t=="history": await ws.send_json({"type":"history","history":mem_history.get(sid,[])}); continue
                    if t=="stats": st=mem_stats.get(sid,{}); await ws.send_json({"type":"stats","command_count":st.get("command_count",0),"session_id":sid}); continue
                except Exception: pass
            try: await track(sid,data); proc.stdin.write(data.encode()); await proc.stdin.drain()
            except Exception: break
        elif msg.type in (aiohttp.WSMsgType.CLOSE,aiohttp.WSMsgType.ERROR): break
    try: proc.kill()
    except Exception: pass

# ── Live view WebSocket ────────────────────────────────────────────────────────

async def route_watch(request):
    sid = request.match_info.get("sid","")
    if sid not in active_ws:
        return web.Response(status=404, text="Session not active")
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    if sid not in watchers: watchers[sid] = []
    watchers[sid].append(ws)
    await ws.send_str(f"\x1b[90m[Live view — session {sid}]\x1b[0m\r\n")
    async for msg in ws:
        pass  # read-only
    if sid in watchers and ws in watchers[sid]:
        watchers[sid].remove(ws)
    return ws

# ── HTTP routes ────────────────────────────────────────────────────────────────

async def route_dashboard(request):
    return web.Response(text=DASHBOARD, content_type="text/html")

async def route_api(request):
    try:
        data = await asyncio.to_thread(db_dashboard_data)
        return web.Response(text=json.dumps(data), content_type="application/json",
                            headers={"Access-Control-Allow-Origin":"*"})
    except Exception as e:
        return web.Response(status=500, text=str(e))

async def route_kill(request):
    sid = request.match_info.get("sid","")
    ws  = active_ws.get(sid)
    if not ws:
        return web.Response(status=404, text="Session not found or already closed")
    await ws.close()
    return web.Response(text=json.dumps({"ok":True}), content_type="application/json",
                        headers={"Access-Control-Allow-Origin":"*"})

async def route_ack_alerts(request):
    await db_ack_alerts()
    return web.Response(text=json.dumps({"ok":True}), content_type="application/json",
                        headers={"Access-Control-Allow-Origin":"*"})

async def route_login_get(request):
    if check_session(request):
        raise web.HTTPFound("/")
    return web.Response(text=LOGIN_HTML, content_type="text/html")

async def route_login_post(request):
    ip = request.headers.get("X-Forwarded-For", request.remote or "").split(",")[0].strip()
    if not check_rate_limit(ip):
        return web.Response(text=LOGIN_HTML.replace("<!--ERROR-->",
            '<div class="err">Too many attempts. Wait 60 seconds.</div>'),
            content_type="text/html", status=429)
    data = await request.post()
    if data.get("password","") == DASHBOARD_PASS:
        token = make_session()
        signed = f"{token}.{_sign(token)}"
        resp = web.HTTPFound("/")
        resp.set_cookie(COOKIE_NAME, signed, max_age=86400*7,
                        httponly=True, samesite="Lax")
        raise resp
    return web.Response(text=LOGIN_HTML.replace("<!--ERROR-->",
        '<div class="err">Incorrect password.</div>'),
        content_type="text/html", status=401)

async def route_logout(request):
    token_raw = request.cookies.get(COOKIE_NAME,"")
    if token_raw and "." in token_raw:
        dash_sessions.pop(token_raw.rsplit(".",1)[0], None)
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE_NAME)
    raise resp

# ── Dashboard HTML ─────────────────────────────────────────────────────────────

DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kali Terminal — Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.9.0/lib/addon-fit.js"></script>
<style>
:root{--bg:#0a0e17;--bg2:#0f1521;--bg3:#161d2e;--green:#00ff41;--cyan:#00d4ff;--red:#ff4444;--yellow:#ffd700;--orange:#ff8c00;--dim:#3a4a5a;--dim2:#6a7a8a;--fg:#c8d8e8}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:'Courier New',monospace;font-size:13px;min-height:100vh}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.07) 2px,rgba(0,0,0,.07) 4px);pointer-events:none;z-index:9998}
header{background:var(--bg2);border-bottom:1px solid var(--dim);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.logo{color:var(--green);font-size:13px;font-weight:bold;letter-spacing:2px;text-shadow:0 0 12px #00ff4155}
.logo em{color:var(--cyan);font-style:normal}
#hdr-right{display:flex;align-items:center;gap:10px}
#countdown{color:var(--dim2);font-size:11px}
#alert-badge{background:var(--red);color:#fff;font-size:10px;padding:2px 8px;border-radius:10px;font-weight:bold;display:none;cursor:pointer}
#alert-badge:hover{opacity:.85}
.hdr-btn{background:var(--bg3);border:1px solid var(--dim);color:var(--green);padding:5px 12px;font-family:'Courier New',monospace;font-size:11px;cursor:pointer;border-radius:3px}
.hdr-btn:hover{border-color:var(--green)}
main{padding:20px 24px;max-width:1280px;margin:0 auto}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.stat{background:var(--bg2);border:1px solid var(--dim);border-radius:6px;padding:18px 14px;text-align:center;transition:border-color .2s}
.stat:hover{border-color:var(--dim2)}
.stat .n{font-size:36px;font-weight:bold;display:block;line-height:1}
.n.g{color:var(--green);text-shadow:0 0 10px #00ff4133}
.n.c{color:var(--cyan);text-shadow:0 0 10px #00d4ff33}
.n.y{color:var(--yellow);text-shadow:0 0 10px #ffd70033}
.n.r{color:var(--red);text-shadow:0 0 10px #ff444433}
.stat .lbl{color:var(--dim2);font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-top:6px;display:block}
.card{background:var(--bg2);border:1px solid var(--dim);border-radius:6px;margin-bottom:18px;overflow:hidden}
.card.alert-card{border-color:#ff444455}
.card-head{padding:11px 16px;border-bottom:1px solid var(--dim);display:flex;align-items:center;justify-content:space-between;background:var(--bg3)}
.alert-card .card-head{background:#ff444410;border-bottom-color:#ff444433}
.card-head h2{color:var(--cyan);font-size:11px;text-transform:uppercase;letter-spacing:1.5px}
.alert-card .card-head h2{color:var(--red)}
.card-head .badge{color:var(--dim2);font-size:10px;background:var(--bg2);border:1px solid var(--dim);padding:2px 8px;border-radius:10px}
.ack-btn{background:none;border:1px solid #ff444455;color:var(--red);font-family:'Courier New',monospace;font-size:10px;padding:2px 10px;border-radius:3px;cursor:pointer}
.ack-btn:hover{background:#ff444415}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 14px;color:var(--dim2);font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--dim);white-space:nowrap}
td{padding:9px 14px;border-bottom:1px solid #ffffff05;font-size:12px;vertical-align:middle;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:#ffffff03}
.sid{color:var(--green);font-size:11px;font-family:'Courier New',monospace}
.cmd-text{color:var(--fg);font-family:'Courier New',monospace}
.ts{color:var(--dim2);font-size:11px}
.ip{color:var(--cyan);font-size:11px;font-family:'Courier New',monospace}
.kw{color:var(--orange);font-size:10px;background:#ff8c0015;border:1px solid #ff8c0044;padding:1px 6px;border-radius:3px}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;letter-spacing:.5px;text-transform:uppercase}
.pill-on{background:#00ff4115;color:var(--green);border:1px solid #00ff4130}
.pill-off{background:#ffffff08;color:var(--dim2);border:1px solid var(--dim)}
.empty{padding:28px;text-align:center;color:var(--dim2);font-size:12px}
#footer{color:var(--dim2);font-size:10px;text-align:right;padding:4px 0 16px}
.act-btn{background:none;font-family:'Courier New',monospace;font-size:10px;padding:2px 8px;border-radius:3px;cursor:pointer;letter-spacing:.5px;margin-right:4px}
.kill-btn{border:1px solid #ff444455;color:var(--red)}
.kill-btn:hover{background:#ff444415;border-color:var(--red)}
.watch-btn{border:1px solid #00d4ff55;color:var(--cyan)}
.watch-btn:hover{background:#00d4ff15;border-color:var(--cyan)}
.act-btn:disabled{opacity:.4;cursor:default}

/* Live view modal */
#modal{display:none;position:fixed;inset:0;background:#000000cc;z-index:200;align-items:center;justify-content:center}
#modal.open{display:flex}
#modal-box{background:var(--bg2);border:1px solid var(--cyan);border-radius:8px;width:90vw;max-width:900px;height:70vh;display:flex;flex-direction:column;overflow:hidden}
#modal-head{padding:10px 16px;border-bottom:1px solid var(--dim);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
#modal-title{color:var(--cyan);font-size:12px;font-weight:bold;letter-spacing:1px}
#modal-close{background:none;border:none;color:var(--dim2);font-size:20px;cursor:pointer;line-height:1}
#modal-close:hover{color:var(--red)}
#modal-term{flex:1;background:#000;overflow:hidden}
</style>
</head>
<body>
<header>
  <div class="logo">KALI<em>TERMINAL</em> &nbsp;·&nbsp; Dashboard</div>
  <div id="hdr-right">
    <span id="countdown">refresh in 30s</span>
    <span id="alert-badge" onclick="scrollToAlerts()">⚠ 0 alerts</span>
    <button class="hdr-btn" onclick="load()">↺ Refresh</button>
    <a href="/logout"><button class="hdr-btn" style="color:#ff4444;border-color:#ff444455">⏻ Logout</button></a>
  </div>
</header>

<main>
  <div class="stats">
    <div class="stat"><span class="n g" id="n-sess">—</span><span class="lbl">Total Sessions</span></div>
    <div class="stat"><span class="n c" id="n-active">—</span><span class="lbl">Active Now</span></div>
    <div class="stat"><span class="n y" id="n-cmds">—</span><span class="lbl">Commands Run</span></div>
    <div class="stat"><span class="n r" id="n-alerts">—</span><span class="lbl">Alerts</span></div>
  </div>

  <!-- Alerts -->
  <div class="card alert-card" id="alerts-card" style="display:none">
    <div class="card-head">
      <h2>⚠ Keyword Alerts</h2>
      <button class="ack-btn" onclick="ackAlerts()">✓ Dismiss All</button>
    </div>
    <div id="alerts-body"></div>
  </div>

  <!-- Sessions -->
  <div class="card">
    <div class="card-head"><h2>Sessions</h2><span class="badge" id="sess-badge">—</span></div>
    <div id="sess-body"><div class="empty">Loading…</div></div>
  </div>

  <!-- Commands -->
  <div class="card">
    <div class="card-head"><h2>Command History</h2><span class="badge" id="cmd-badge">—</span></div>
    <div id="cmd-body"><div class="empty">Loading…</div></div>
  </div>

  <div id="footer">—</div>
</main>

<!-- Live view modal -->
<div id="modal">
  <div id="modal-box">
    <div id="modal-head">
      <span id="modal-title">LIVE VIEW</span>
      <button id="modal-close" onclick="closeWatch()">×</button>
    </div>
    <div id="modal-term"></div>
  </div>
</div>

<script>
let countdown=30, timer, watchWs=null, watchTerm=null, watchFit=null;

function tick(){ countdown--; document.getElementById('countdown').textContent='refresh in '+countdown+'s'; if(countdown<=0){countdown=30;load();} }
function startTimer(){ clearInterval(timer); countdown=30; timer=setInterval(tick,1000); }
function fmt(iso){ if(!iso)return'—'; const d=new Date(iso); return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short'})+' '+d.toLocaleTimeString(); }
function dur(a,b){ if(!a)return'—'; const s=Math.floor((new Date(b||Date.now())-new Date(a))/1000); if(s<60)return s+'s'; if(s<3600)return Math.floor(s/60)+'m'; return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m'; }
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function scrollToAlerts(){ document.getElementById('alerts-card').scrollIntoView({behavior:'smooth'}); }

async function load(){
  startTimer();
  try{
    const d=(await (await fetch('/api/data')).json());
    const {stats,sessions,commands,alerts}=d;
    document.getElementById('n-sess').textContent=stats.total_sessions;
    document.getElementById('n-active').textContent=stats.active_sessions;
    document.getElementById('n-cmds').textContent=stats.total_commands;
    document.getElementById('n-alerts').textContent=stats.alerts;
    document.getElementById('sess-badge').textContent=sessions.length+' rows';
    document.getElementById('cmd-badge').textContent=commands.length+' rows';

    // Alert badge in header
    const ab=document.getElementById('alert-badge');
    if(stats.alerts>0){ ab.textContent='⚠ '+stats.alerts+' alert'+(stats.alerts>1?'s':''); ab.style.display='inline'; }
    else ab.style.display='none';

    // Alerts card
    const ac=document.getElementById('alerts-card');
    if(alerts.length){
      ac.style.display='block';
      let h='<table><thead><tr><th>Time</th><th>Session</th><th>Command</th><th>Keyword</th></tr></thead><tbody>';
      alerts.forEach(a=>{ h+=`<tr><td class="ts">${fmt(a.triggered_at)}</td><td class="sid">${a.session_id}</td><td class="cmd-text">${esc(a.command)}</td><td><span class="kw">${esc(a.keyword)}</span></td></tr>`; });
      document.getElementById('alerts-body').innerHTML=h+'</tbody></table>';
    } else { ac.style.display='none'; }

    // Sessions
    if(!sessions.length){
      document.getElementById('sess-body').innerHTML='<div class="empty">No sessions yet</div>';
    } else {
      let h='<table><thead><tr><th>ID</th><th>IP</th><th>Connected</th><th>Duration</th><th>Cmds</th><th>Status</th><th></th></tr></thead><tbody>';
      sessions.forEach(s=>{
        const active=!s.disconnected_at;
        const btns=active
          ?`<button class="act-btn watch-btn" onclick="openWatch('${s.session_id}',this)">◉ Watch</button><button class="act-btn kill-btn" onclick="killSession('${s.session_id}',this)">■ Stop</button>`
          :'';
        h+=`<tr><td class="sid">${s.session_id}</td><td class="ip">${esc(s.ip||'—')}</td><td class="ts">${fmt(s.connected_at)}</td><td class="ts">${dur(s.connected_at,s.disconnected_at)}</td><td>${s.command_count}</td><td><span class="pill ${active?'pill-on':'pill-off'}">${active?'● live':'closed'}</span></td><td>${btns}</td></tr>`;
      });
      document.getElementById('sess-body').innerHTML=h+'</tbody></table>';
    }

    // Commands
    if(!commands.length){
      document.getElementById('cmd-body').innerHTML='<div class="empty">No commands yet</div>';
    } else {
      let h='<table><thead><tr><th>Command</th><th>Session</th><th>Time</th></tr></thead><tbody>';
      commands.forEach(c=>{ h+=`<tr><td class="cmd-text">${esc(c.command)}</td><td class="sid">${c.session_id}</td><td class="ts">${fmt(c.executed_at)}</td></tr>`; });
      document.getElementById('cmd-body').innerHTML=h+'</tbody></table>';
    }

    document.getElementById('footer').textContent='Last updated: '+new Date().toLocaleTimeString();
  }catch(e){ document.getElementById('footer').textContent='Error: '+e; }
}

async function killSession(sid,btn){
  if(!confirm('Stop session '+sid+'?')) return;
  btn.disabled=true; btn.textContent='...';
  try{
    const r=await fetch('/api/kill/'+sid,{method:'POST'});
    if(r.ok){btn.textContent='✓';setTimeout(load,800);}
    else{btn.textContent='✗';btn.disabled=false;}
  }catch(e){btn.textContent='✗';btn.disabled=false;}
}

async function ackAlerts(){
  await fetch('/api/alerts/ack',{method:'POST'});
  load();
}

// ── Live view ──────────────────────────────────────────────────────────────────
function openWatch(sid){
  const modal=document.getElementById('modal');
  document.getElementById('modal-title').textContent='LIVE VIEW — '+sid;
  modal.className='open';

  if(watchTerm){watchTerm.dispose();watchTerm=null;}
  if(watchWs){watchWs.close();watchWs=null;}

  watchTerm=new Terminal({
    theme:{background:'#000',foreground:'#c8d8e8',cursor:'#00ff41'},
    fontFamily:'"Courier New",monospace',fontSize:13,lineHeight:1.2,
    cursorBlink:true,scrollback:2000
  });
  watchFit=new FitAddon.FitAddon();
  watchTerm.loadAddon(watchFit);
  watchTerm.open(document.getElementById('modal-term'));
  watchFit.fit();

  const proto=location.protocol==='https:'?'wss':'ws';
  watchWs=new WebSocket(`${proto}://${location.host}/api/watch/${sid}`);
  watchWs.onmessage=e=>watchTerm.write(e.data);
  watchWs.onclose=()=>watchTerm.write('\r\n\x1b[90m[Session ended]\x1b[0m\r\n');
}

function closeWatch(){
  if(watchWs){watchWs.close();watchWs=null;}
  if(watchTerm){watchTerm.dispose();watchTerm=null;}
  document.getElementById('modal').className='';
}

window.addEventListener('resize',()=>{ if(watchFit) watchFit.fit(); });
document.getElementById('modal').addEventListener('click',e=>{ if(e.target===document.getElementById('modal'))closeWatch(); });

load();
</script>
</body>
</html>"""

# ── Login page HTML ───────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kali Terminal — Login</title>
<style>
:root{--bg:#0a0e17;--bg2:#0f1521;--green:#00ff41;--cyan:#00d4ff;--red:#ff4444;--dim:#3a4a5a;--dim2:#6a7a8a;--fg:#c8d8e8}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:'Courier New',monospace;height:100vh;display:flex;align-items:center;justify-content:center}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.08) 2px,rgba(0,0,0,.08) 4px);pointer-events:none}
.box{background:var(--bg2);border:1px solid var(--dim);border-radius:8px;padding:36px 32px;width:320px;text-align:center}
.logo{color:var(--green);font-size:9px;line-height:1.15;white-space:pre;font-weight:bold;text-shadow:0 0 10px #00ff4155;margin-bottom:18px;animation:pulse 3s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.7}}
h2{color:var(--cyan);font-size:14px;letter-spacing:2px;text-transform:uppercase;margin-bottom:20px}
label{display:block;color:var(--dim2);font-size:10px;text-transform:uppercase;letter-spacing:1px;text-align:left;margin-bottom:5px}
input[type=password]{width:100%;background:#161d2e;border:1px solid var(--dim);border-radius:4px;color:var(--fg);font-family:'Courier New',monospace;font-size:14px;padding:10px 12px;outline:none;margin-bottom:16px;transition:border-color .2s}
input[type=password]:focus{border-color:var(--green)}
button{width:100%;background:linear-gradient(135deg,#00cc33,var(--green));color:#000;border:none;border-radius:4px;padding:12px;font-family:'Courier New',monospace;font-size:13px;font-weight:bold;cursor:pointer;letter-spacing:1px;box-shadow:0 0 12px #00ff4133}
button:hover{opacity:.9}
.err{color:var(--red);font-size:11px;margin-bottom:12px;padding:8px;background:#ff444415;border:1px solid #ff444433;border-radius:4px}
</style>
</head>
<body>
<div class="box">
  <div class="logo">  ██╗  ██╗ █████╗ ██╗     ██╗
  ██║ ██╔╝██╔══██╗██║     ██║
  █████╔╝ ███████║██║     ██║
  ██╔═██╗ ██╔══██║██║     ██║
  ██║  ██╗██║  ██║███████╗██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝</div>
  <h2>Dashboard Login</h2>
  <!--ERROR-->
  <form method="POST" action="/login">
    <label>Password</label>
    <input type="password" name="password" autofocus autocomplete="current-password">
    <button type="submit">▶ &nbsp; ENTER</button>
  </form>
</div>
</body>
</html>"""

# ── Main ───────────────────────────────────────────────────────────────────────

async def main():
    await init_db()
    mode = "PTY" if USE_PTY else "pipe"
    ip   = get_server_ip()
    print(f"\n  Kali Terminal Server v5 [{mode} mode]", flush=True)
    print(f"  Shell:     {' '.join(get_shell())}", flush=True)
    print(f"  WS URL:    ws://{ip}:{PORT}/ws", flush=True)
    print(f"  Dashboard: http://{ip}:{PORT}/", flush=True)
    print(f"  Token:     {TOKEN}\n", flush=True)

    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get("/",                  route_dashboard)
    app.router.add_get("/login",             route_login_get)
    app.router.add_post("/login",            route_login_post)
    app.router.add_get("/logout",            route_logout)
    app.router.add_get("/api/data",          route_api)
    app.router.add_post("/api/kill/{sid}",   route_kill)
    app.router.add_post("/api/alerts/ack",   route_ack_alerts)
    app.router.add_get("/api/watch/{sid}",   route_watch)
    app.router.add_get("/ws",                ws_handler)
    app.router.add_get("/ws/",               ws_handler)
    app.router.add_get("/terminal",          ws_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    await asyncio.Future()

asyncio.run(main())
