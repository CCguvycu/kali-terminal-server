"""
Kali Terminal — internal API client
Wraps the REST API so the server never touches the database directly.
"""
import asyncio, os
import aiohttp

API_URL  = os.environ.get("API_URL",  "https://kali-terminal-api-production.up.railway.app")
API_PASS = os.environ.get("API_PASSWORD", "kali2024")

_token:   str | None = None
_session: aiohttp.ClientSession | None = None

async def _get_session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession()
    return _session

async def _get_token() -> str:
    global _token
    if _token:
        return _token
    s = await _get_session()
    async with s.post(f"{API_URL}/api/v1/auth/login",
                      data={"username": "server", "password": API_PASS}) as r:
        if r.status == 200:
            _token = (await r.json())["access_token"]
            return _token
        raise RuntimeError(f"API login failed: {r.status}")

async def _call(method: str, path: str, **kwargs) -> dict:
    """Make an authenticated API call; retry once if token expired."""
    global _token
    token = await _get_token()
    s = await _get_session()
    headers = {"Authorization": f"Bearer {token}"}
    for attempt in range(2):
        async with getattr(s, method)(f"{API_URL}{path}", headers=headers, **kwargs) as r:
            if r.status == 401 and attempt == 0:
                _token = None   # force re-login
                token = await _get_token()
                headers["Authorization"] = f"Bearer {token}"
                continue
            if r.status in (200, 201, 204):
                try:    return await r.json()
                except: return {}
            return {}
    return {}

# ── Public helpers ─────────────────────────────────────────────────────────────

async def start_session(sid: str, shell: str, ip: str):
    """Called when a new terminal session opens."""
    await _call("post", "/api/v1/sessions/internal/start",
                json={"session_id": sid, "shell": shell, "ip_address": ip})

async def end_session(sid: str, command_count: int):
    """Called when a terminal session closes."""
    await _call("post", f"/api/v1/sessions/internal/{sid}/end",
                json={"command_count": command_count})

async def log_command(sid: str, command: str):
    """Log a command to the API."""
    await _call("post", "/api/v1/commands/internal",
                json={"session_id": sid, "command": command})

async def log_alert(sid: str, command: str, keyword: str):
    """Log a keyword alert to the API."""
    await _call("post", "/api/v1/alerts/internal",
                json={"session_id": sid, "command": command, "keyword": keyword})

async def get_history(sid: str) -> list:
    """Get command history for a session (for the in-app history panel)."""
    data = await _call("get", f"/api/v1/sessions/{sid}/commands?limit=100")
    return [{"cmd": c["command"], "ts": c["executed_at"]}
            for c in data.get("commands", [])]

async def get_stats() -> dict:
    return await _call("get", "/api/v1/stats")

async def get_dashboard_data() -> dict:
    stats, sessions, commands, alerts = await asyncio.gather(
        _call("get", "/api/v1/stats"),
        _call("get", "/api/v1/sessions?limit=50"),
        _call("get", "/api/v1/commands?limit=100"),
        _call("get", "/api/v1/alerts?acknowledged=false&limit=50"),
    )
    return {
        "stats": {
            "total_sessions":  stats.get("total_sessions", 0),
            "active_sessions": stats.get("active_sessions", 0),
            "total_commands":  stats.get("total_commands", 0),
            "sessions_today":  stats.get("sessions_today", 0),
            "alerts":          stats.get("unread_alerts", 0),
        },
        "sessions": sessions.get("sessions", []),
        "commands": commands.get("commands", []),
        "alerts":   alerts.get("alerts", []),
    }
