# GymTracker

A Flask and SQLite app for managing workout plans, exercises, profiles, and training records.

## Run

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Data is stored in `instance/database.db`. On restart, an existing `.venv/database.db` is copied automatically if the new database does not exist; the original is kept as a backup. Stop the old server before restarting.

## Tests

```powershell
python -B -m unittest discover -s tests -v
```
