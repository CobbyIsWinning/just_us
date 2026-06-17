# Just Us

Secure room messaging MVP built with FastAPI, Jinja templates, Tailwind, and Neon.

## Local run

```bash
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000`.

## Vercel deployment

The app is configured for Vercel with `vercel.json`, which routes all requests to
the FastAPI ASGI app in `main.py`.

Set these environment variables in Vercel:

```txt
DATABASE_URL
SECRET_KEY
APP_MASTER_KEY
```

Security events are written to the `security_logs` table in Neon. A local file log
is kept only as a development fallback.

Developer/demo routes are still available directly:

```txt
/logs
/attacks
/dev/storage
```
