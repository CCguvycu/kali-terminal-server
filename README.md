# Kali Terminal Server

WebSocket terminal server that powers the Kali Terminal Android app. Runs a real Kali Linux PTY session per connection, stores session/command history in PostgreSQL, and serves a live admin dashboard.

## Features

- **PTY mode** — real terminal (colours, `vim`, `top`, `ls` columns all work)
- **PostgreSQL** — every session and command logged with timestamps and client IP
- **Live dashboard** — view sessions, commands, alerts at `/`
- **Live view** — watch any active session in real time from the dashboard
- **Keyword alerts** — flags dangerous commands (`rm -rf`, `nc -e`, etc.)
- **Dashboard auth** — password-protected login with rate limiting
- **Kill sessions** — stop any active connection from the dashboard

## Stack

- Python 3 + aiohttp (HTTP + WebSocket on one port)
- pg8000 (PostgreSQL driver, pure Python)
- Deployed on Railway

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `KALI_TOKEN` | Token required by the Android app to connect | `kali2024` |
| `DASHBOARD_PASS` | Dashboard login password | `changeme` |
| `DATABASE_URL` | PostgreSQL connection string | — |
| `PORT` | Listen port (set by Railway automatically) | `8765` |

## Deploy to Railway

```bash
railway login
railway init
railway up
railway add -d postgres
railway variables --set "KALI_TOKEN=yourtoken"
railway variables --set "DASHBOARD_PASS=yourpassword"
railway domain
```

## Dashboard

Open `https://<your-railway-domain>/` in any browser.

| Feature | Description |
|---|---|
| Sessions | All connections with IP, duration, command count |
| Commands | Full command history across all sessions |
| Alerts | Commands matching dangerous keyword patterns |
| Live View | Real-time terminal mirror of any active session |
| Kill | Instantly close any active session |

## Local Run

```bash
pip install aiohttp pg8000
python server.py
```

## WebSocket URL

```
wss://<your-domain>/ws?token=<KALI_TOKEN>
```

## Alert Keywords

Commands containing any of these trigger an alert:

`rm -rf` · `/etc/shadow` · `nc -e` · `bash -i` · `chmod 777` · `mkfs` · `dd if=` · `base64 -d` · `python -c` · `:(){:|:&};:`
