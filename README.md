# SecureExam — Secure. Resilient. Transparent.
**Team Explorer** · MPOnline Limited Idea & Innovation Hackathon 2026 · Challenge 6 — Resilient & Trustworthy Online Assessment Ecosystem

A student-built, working MVP of an online exam platform whose hero feature is **network-failure recovery**: answers are saved in the browser first, queued while offline, and synchronized (with audit records) when the connection returns.

## Run locally (2 commands)
```bash
pip install -r requirements.txt
python app.py            # open http://127.0.0.1:5000  (DB auto-created and seeded)
```
Tests: `python -m unittest discover -s tests -v` · Env vars: see `.env.example` (`SECRET_KEY`, `DATABASE_PATH`, `PORT`, `SESSION_COOKIE_SECURE`).

## Demo accounts (DEMONSTRATION ONLY — never use in production)
| Role | Email | Password |
|---|---|---|
| Admin | admin@secureexam.demo | Admin@1234 |
| Student | student@secureexam.demo | Demo@1234 |
Other seeded students: student2..student7@secureexam.demo (same password). Reset demo data: delete `secureexam.db`.

## Architecture
```
Student Browser (SPA: static/index.html)
   │  answers → localStorage queue ──(offline)──▶ pending
   ▼                                   (online / "Restore Network")
REST API (Flask, app.py) ◀──────────── POST /api/attempts/:id/sync
   ├─ Auth (sessions, hashed pw, RBAC, rate limit)
   ├─ Exam engine (server-side timing + grading)
   └─ SQLite ──▶ audit_logs · suspicious_events · sync_events ──▶ Admin monitoring
```
Tables: users, exams, questions, attempts, answers, audit_logs, suspicious_events, sync_events (foreign keys + indexes; plain SQL, portable to PostgreSQL/MySQL).

## Network resilience (implemented)
1. Selecting an answer writes `{ts, selected, pending}` to `localStorage` immediately, then a debounced (400 ms) sync is attempted.
2. Offline (real `offline` event, `navigator.onLine`, or the **Demo Mode: Simulate Network Failure** button): UI shows *Connection Lost — Answers saved locally*; student keeps answering; a `NETWORK_LOST` event is queued.
3. On restore: `NETWORK_RESTORED` queued, all pending answers + events sent in one `POST /sync`; server acknowledges accepted question IDs; only those are cleared locally; UI shows *Connection Restored — Answers Synchronized*.
4. Conflict rule: newest client timestamp wins per question; older writes are acknowledged but ignored; future timestamps are clamped to server time; answers stamped after deadline (+10 s grace) are rejected and logged.
5. Refreshing/closing the browser keeps the queue (localStorage); resuming the attempt merges it.
**Honesty note:** the simulate button is a controlled demonstration (it blocks sync calls); it does not reproduce every real-world network failure (e.g. captive portals, packet loss).

## Security (implemented)
Password hashing (Werkzeug scrypt) · server-side sessions cookie (HttpOnly, SameSite=Lax) · role checks on every protected route · login rate limit (5 fails / 5 min, in-memory) · parameterized SQL only · input validation · correct answers never sent to students; grading and deadline enforced on server · per-student attempt isolation · security headers/CSP · secrets from env (random key if unset) · audit log of unauthorized access.

## Suspicious activity (rule-based, NOT AI)
Tab switching (`visibilitychange`): 5 in 2 min → MEDIUM, 8 → HIGH · 3 disconnects in 10 min → MEDIUM · 3 failed logins → MEDIUM · 15 answer changes in 10 s → LOW. It only *records* behaviours for human review; it does not prevent cheating and can produce false positives.

## API (all JSON)
`POST /api/auth/{register,login,logout}` · `GET /api/auth/me` · `GET|POST /api/exams` · `GET|PUT|DELETE /api/exams/:id` · `POST /api/exams/:id/questions` · `PUT|DELETE /api/questions/:id` · `POST /api/exams/:id/start` · `GET /api/attempts/:id` · `POST /api/attempts/:id/{answers,sync,events,submit}` · `GET /api/admin/{dashboard,audit-logs,suspicious-events,monitoring,students}`

## Demo script (≈7 min)
1. Login as student → Start "Data Structures Mid-Term" → answer 2 questions (status *Saved/Synced ✓*).
2. Click **Simulate Network Failure** → banner *Connection Lost*; answer 3 more (pending count shown).
3. Click **Restore Network** → *Synchronizing…* → *Answers Synchronized*. Switch tab once and return (warning shown). Submit → result.
4. Login as admin (other browser/incognito) → Monitoring: attempt, score, drops, syncs, flags → Audit Logs: filter `NETWORK_LOST`, `ANSWERS_SYNCHRONIZED` → Suspicious activity table → Overview analytics.

## Known limitations
No email verification/2FA/password reset · SQLite single-node · in-memory rate limiter · CSRF relies on SameSite+JSON · no IP/multi-session binding · offline students can't submit until reconnecting (auto-submit on restore) · tab detection is easily bypassed and is only a signal · no proctoring/biometrics by design · no load testing done · Demo timer uses client clock offset corrected at load, server is authoritative.

## Deployment (free tier)
Render/Railway: build `pip install -r requirements.txt`, start `gunicorn app:app` (add `gunicorn` to requirements), set `SECRET_KEY`, `SESSION_COOKIE_SECURE=1`. For persistence use a disk or migrate to PostgreSQL (change `sqlite3` calls to `psycopg`). Scale path: stateless API behind a load balancer, Postgres + read replicas, Redis for rate limits/sessions, queue for audit writes.

## Future scope
2FA, SEB/lockdown integration, per-exam scheduling windows, question banks, Service Worker/IndexedDB for full offline shell, Postgres, load testing, optional AI risk summary for reviewers, Hindi UI.

## GitHub upload
```bash
git init && git add . && git commit -m "SecureExam MVP - Team Explorer"
git branch -M main && git remote add origin <your-repo-url> && git push -u origin main
```
