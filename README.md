# Kali Terminal — WebSocket Server

The core backend of the Kali Terminal platform. Runs a real Linux PTY session per connection, streams it over WebSocket to the Android app, and reports everything to the REST API. Also serves the live admin dashboard.

**Live:** `https://kali-terminal-production.up.railway.app`

---

## How it fits in

```
Android App  ──WebSocket──▶  This server  ──HTTP/JWT──▶  REST API  ──▶  PostgreSQL
Dashboard    ──────────────────────────────────────────▶  REST API
```

The server never touches the database directly. All session, command, and alert data is written through the [kali-terminal-api](https://github.com/CCguvycu/kali-terminal-api).

---

## Features

- **PTY mode** — real terminal emulation (colours, `vim`, `top`, resize all work)
- **Live view** — watch any active session in real time from the dashboard
- **Keyword alerts** — flags dangerous commands (`rm -rf`, `nc -e`, etc.)
- **Kill sessions** — drop any active connection instantly from the dashboard
- **IP logging** — real client IP captured via `X-Forwarded-For`
- **Dashboard auth** — HMAC-signed cookies, 7-day expiry, per-IP rate limiting
- **Bearer JWT auth** — dashboard API endpoints accept JWT tokens for remote access
- **Auto deploy** — GitHub Actions deploys to Railway on every push to `master`

---

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `KALI_TOKEN` | Token required by the Android app to connect | `kali2024` |
| `DASHBOARD_PASS` | Dashboard login password | `changeme` |
| `API_URL` | Base URL of the REST API | `https://kali-terminal-api-production.up.railway.app` |
| `API_PASSWORD` | Password used to authenticate with the REST API | `kali2024` |
| `JWT_SECRET` | Secret for validating Bearer JWT tokens | `change-this-secret-in-production` |
| `PORT` | Listen port (set by Railway automatically) | `8765` |

---

## Running locally

```bash
pip install -r requirements.txt

export KALI_TOKEN=yourtoken
export DASHBOARD_PASS=yourpassword
export API_URL=https://kali-terminal-api-production.up.railway.app
export API_PASSWORD=yourpassword

python server.py
```

WebSocket: `ws://localhost:8765/ws?token=<KALI_TOKEN>`  
Dashboard: `http://localhost:8765/`

---

## Dashboard

Open `https://<your-domain>/` in any browser and log in with `DASHBOARD_PASS`.

| Feature | Description |
|---|---|
| Sessions | All connections with IP, duration, command count, live/closed status |
| Commands | Full command history across all sessions |
| Alerts | Commands matching dangerous keyword patterns |
| Live View | Real-time terminal mirror of any active session |
| Kill | Instantly close any active session |

The dashboard is also accessible remotely at `https://ccguvycu.github.io/dashboard.html` using the REST API password.

---

## WebSocket protocol

Connect with:
```
wss://<your-domain>/ws?token=<KALI_TOKEN>
```

Send JSON frames to control the session:

| Frame | Description |
|---|---|
| `{"type":"resize","rows":40,"cols":120}` | Resize the PTY |
| `{"type":"history"}` | Request command history |
| `{"type":"stats"}` | Request session stats |

All other text is forwarded directly to the PTY as input.

---

## Alert keywords

Commands containing any of these trigger an alert logged to the REST API:

`rm -rf` · `/etc/shadow` · `/etc/passwd` · `nc -e` · `bash -i` · `chmod 777` · `mkfs` · `dd if=` · `base64 -d` · `python -c` · `:(){:|:&};:`

---

## Related repos

- [kali-terminal-api](https://github.com/CCguvycu/kali-terminal-api) — REST API (FastAPI + PostgreSQL)
- [kali-terminal-android](https://github.com/CCguvycu/kali-terminal-android) — Android app

## License

MIT
