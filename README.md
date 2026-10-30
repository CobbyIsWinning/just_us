# Just Us

Secure room messaging MVP built with FastAPI, Jinja templates, shared CSS components, and SQLAlchemy.

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
3. Send a message in the room conversation.
4. Register another user in a different browser or after logging out.
5. Open **Private inbox**, choose a recipient, and send a private message.
   The `@username message text` shortcut also works from a room.
6. Use **Activity**, **Security lab**, or **Storage** in the main navigation
   for the security demo pages.
7. Create or join rooms from **Create or join a room** in the conversations sidebar.

The interface supports mobile and desktop layouts, keyboard message submission
(Enter to send, Shift + Enter for a new line), event filtering, and expandable
encrypted storage records. Messages update when you send or use the refresh button.

## Vercel deployment

The app uses Vercel's native FastAPI support, configured in `vercel.json`.
Vercel detects `app` in `main.py` and preserves incoming request paths.
Do not add a catch-all rewrite to `/main.py`: that changes the path FastAPI
receives and causes `{"detail":"Not Found"}` responses.

After deploying, open `/health` to check the application, then `/` to reach
the login page.

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
