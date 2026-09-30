# 10-slide outline (5–10 min)
1. **Title** — SecureExam: Secure. Resilient. Transparent. Team Explorer. *Notes:* introduce challenge 6.
2. **Problem** — dropped connections, lost answers, weak auth, no audit trail. *Notes:* one real example.
3. **Solution** — local-first answers + sync, server-authoritative exam, audit trail.
4. **Key features** — auto-save, offline queue, RBAC, monitoring, suspicious-activity rules, analytics.
5. **Architecture** — Browser → REST API → SQLite → audit/monitoring (diagram in README).
6. **Security** — hashing, sessions, RBAC, server grading/timing, rate limit, no answer keys to client; honest: not "unhackable".
7. **Resilience** — disconnect → queue → reconnect → sync → logged. *Notes:* say the button is a controlled simulation.
8. **Tech stack** — Flask, SQLite, vanilla JS, localStorage.
9. **Impact + scalability** — Postgres, load balancer, Redis, queued audit writes; not yet load-tested.
10. **Live demo + future scope** — run the demo script; future: 2FA, IndexedDB/Service Worker, lockdown browser, Postgres.
