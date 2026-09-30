# SecureExam — Team Explorer · Challenge 6
**Problem:** Online exams fail when connections drop, answers are lost, logins are weak and there is no transparent record of what happened.
**Solution:** SecureExam — local-first answer storage with a sync queue, server-authoritative timing/grading, role-based access and a full audit trail with rule-based suspicious-activity flags.
**Innovation:** Exam continuity under network interruption with verifiable recovery: every disconnect, reconnect and synchronization is logged and visible to admins.
**Implemented:** register/login/logout, RBAC, exam+question management, randomized question and option order, timer with server validation, auto-save, offline queue + sync, tab-switch detection, audit logs with filters, suspicious-event dashboard, monitoring, analytics, seeded demo data, 5 automated test groups.
**Stack:** Python Flask, SQLite, vanilla JS SPA, localStorage.
**Security:** hashed passwords, sessions (HttpOnly/SameSite), server-side authorization and grading, parameterized SQL, rate limiting, CSP headers, no answer keys sent to clients.
**Impact:** fewer lost/disputed attempts and auditable exams for colleges and large-scale examinations.
**Scalability:** stateless API + Postgres + Redis + load balancer (design; not load-tested).
**Prototype status/limitations:** see README (no 2FA, single-node SQLite, tab detection is only a signal, network failure is a controlled simulation).
