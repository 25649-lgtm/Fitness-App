# Password and training-access improvement

Date: 2026-09-21

## Problem found by code inspection

Registration stored passwords as plain text and login compared them directly.
The training detail route did not require login or check plan ownership.

## Changes

- Registration uses Werkzeug's salted password hashing; login verifies hashes.
- A `password_hashed` field marks migrated accounts. On startup, existing plain
  text passwords are hashed in a transaction. Subsequent startups leave them
  unchanged, and existing passwords continue to work.
- Login tolerates missing fields and normalizes email in the same way as signup.
- Training details require login and return 404 for another user's training.
- `GYMTRACKER_DATABASE` allows tests to use temporary storage before app import.

## Actual verification

Run from the Jerry directory:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

| Automated test | Verified result |
| --- | --- |
| Registration storage | Password is hashed; equal passwords have different hashes |
| Correct login | Login succeeds, including normalized email |
| Invalid credentials | Wrong, empty and missing credentials do not authenticate |
| Duplicate registration | Existing email is rejected |
| Legacy migration | Original schema migrates, login works, repeat initialization does not rehash |
| Training permissions | Anonymous access redirects; owner gets 200; another user and missing ID get 404 |

First run: five tests passed; migration test failed during temporary-file cleanup
because SQLite connections remained open on Windows. Added explicit connection
closing to initialization and test database access. Second run: all six passed.

Tests used synthetic accounts and temporary databases. The real database was not
migrated during this verification; migration runs on the next application start.
Migration changes current stored values but is not forensic removal of historical
plain text from old backups or SQLite free pages.

## Scope remaining

The hard-coded session secret, CSRF protection and broader form validation still
need separate work. This change does not establish complete application security.
No browser usability test was performed in this step.
