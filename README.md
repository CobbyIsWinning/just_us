# Just Us

Secure room messaging MVP built with FastAPI, Jinja templates, Tailwind, and SQLAlchemy.

## Local Run

Use these steps from the project folder:

```bash
deactivate 2>/dev/null || true
rm -rf venv
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000`.

The example `.env` uses SQLite:

```txt
DATABASE_URL=sqlite:///./just_us.db
```

That creates a local `just_us.db` file automatically, so the lecturer can run the
project without needing access to the hosted Neon database.

If port `8000` is already busy, run:

```bash
uvicorn main:app --reload --port 8001
```

Then open `http://127.0.0.1:8001`.

If you already had an old `venv`, recreating it is important. Mixing packages
installed by different Python versions can cause import errors.

## Demo Flow

1. Register a user with a username and a password of at least 8 characters.
2. Log in with that user.
3. Send a normal room message.
4. Register another user in a different browser or after logging out.
5. Send a private message with `@username message text`.
6. Visit `/logs`, `/attacks`, or `/dev/storage` for the security demo pages.

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
