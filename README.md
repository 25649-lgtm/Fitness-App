# GymTracker

A Flask and SQLite workout tracker. Users can create an account, maintain a
fitness profile, build workout plans, browse exercises, and record workout
results.

## Run locally

```powershell
pip install Flask
python app.py
```

Open `http://127.0.0.1:5000`. The SQLite database and starter exercise library
are created automatically on first run.

## Session keys and form security

The application first checks the `GYMTRACKER_SECRET_KEY` environment variable.
Use a random value of at least 32 characters. If it is not configured locally,
the application generates `instance/secret_key` and reuses it on later starts.
Do not publish or commit this file; `.gitignore` excludes the entire `instance`
directory. Changing the key invalidates existing sessions, so users must log in
again. For deployment, use HTTPS and set `SESSION_COOKIE_SECURE=True` in the
Flask configuration. Keep the default setting for local HTTP development.

Every form that changes data must include a hidden `csrf_token` field. Missing
or invalid tokens return HTTP 400; users can reload the page and try again.
Logging out and switching accounts use POST. Visiting `/logout` with GET
returns HTTP 405.

Run the automated tests using a temporary database:

```powershell
.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```
