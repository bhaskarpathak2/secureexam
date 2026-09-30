# Judge Q&A (condensed — honest answers)
**How does offline recovery work?** Answers go to localStorage first, are queued with timestamps, and `POST /sync` sends them when online; only server-acknowledged items are cleared.
**What if the browser closes / internet is lost 10 minutes?** The queue persists in localStorage; reopening resumes the attempt and syncs. Answers stamped after the deadline (+10 s grace) are rejected, so long outages beyond the deadline lose late answers.
**How do you prevent answer manipulation?** Grading and deadlines are server-side; correct answers are never sent to students; question IDs are validated; older/forged timestamps can't overwrite or extend time.
**How is auth secured?** Hashed passwords, HttpOnly SameSite session cookie, RBAC on each route, rate limiting.
**Is it AI? Blockchain?** No. Suspicious activity is transparent rules; blockchain adds cost without solving this problem — a append-only DB audit log fits the prototype.
**Can students cheat?** Yes, no online system is cheat-proof. We detect/record some behaviours (tab switches, reconnect patterns) for human review.
**Tab change?** `TAB_SWITCH`/`TAB_RETURN` logged; repeated switches raise MEDIUM/HIGH flags.
**Server fails?** Students keep answering locally; sync resumes when the API returns. Production needs replicas/failover.
**Scale to 100,000 students?** Stateless API behind a load balancer, PostgreSQL with replicas, Redis for limits, batched audit writes, CDN for static files — untested at that scale.
**Database attacks?** Parameterized queries only, least-privilege DB user in production, input validation.
**Student data?** Minimal data (name, email, activity); no biometrics/video; HTTPS + encrypted DB volume in production.
**Limitations / future?** See README. With more time: 2FA, IndexedDB/Service Worker, scheduling windows, load tests, lockdown browser.
**Why MPOnline?** Reliable, auditable large-scale exams for state institutions with variable connectivity.
**Different from existing systems?** Focus on verifiable recovery: connectivity events and syncs are first-class audit records.
