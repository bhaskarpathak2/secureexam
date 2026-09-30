"""SecureExam backend (Team Explorer) - Flask + SQLite. Run: python app.py"""
import os, re, json, time, random, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, g, has_request_context, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=os.path.join(BASE, "static"))
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
                  MAX_CONTENT_LENGTH=1024 * 1024)
FAILS = {}          # (ip,email) -> [timestamps]  (in-memory rate limiter; use Redis in production)
GRACE = 10          # seconds of grace after deadline for late-arriving synced answers
FMT = "%Y-%m-%dT%H:%M:%S.%fZ"

def dbpath(): return os.environ.get("DATABASE_PATH") or os.path.join(BASE, "secureexam.db")
def now(): return datetime.now(timezone.utc)
def iso(d=None): return (d or now()).strftime(FMT)[:-4] + "Z"
def pt(s):
    try: return datetime.strptime(s, FMT).replace(tzinfo=timezone.utc)
    except Exception: return None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('student','admin')), created TEXT);
CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT DEFAULT '', duration_min INTEGER NOT NULL, published INTEGER DEFAULT 0, created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY, exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE, text TEXT NOT NULL, a TEXT, b TEXT, c TEXT, d TEXT, correct TEXT NOT NULL CHECK(correct IN('A','B','C','D')), marks INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE, started TEXT, deadline TEXT, submitted TEXT, score INTEGER, total INTEGER, status TEXT DEFAULT 'in_progress', order_json TEXT, last_seen TEXT, net TEXT DEFAULT 'online', UNIQUE(user_id,exam_id));
CREATE TABLE IF NOT EXISTS answers(attempt_id INTEGER REFERENCES attempts(id) ON DELETE CASCADE, question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE, selected TEXT, updated TEXT, PRIMARY KEY(attempt_id,question_id));
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER, exam_id INTEGER, type TEXT, severity TEXT DEFAULT 'INFO', meta TEXT, ip TEXT, ua TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS suspicious_events(id INTEGER PRIMARY KEY, user_id INTEGER, exam_id INTEGER, attempt_id INTEGER, rule TEXT, severity TEXT, detail TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS sync_events(id INTEGER PRIMARY KEY, attempt_id INTEGER, user_id INTEGER, count INTEGER, ts TEXT);
CREATE INDEX IF NOT EXISTS ix_audit ON audit_logs(user_id,exam_id,type,ts);
CREATE INDEX IF NOT EXISTS ix_att ON attempts(user_id,exam_id);
CREATE INDEX IF NOT EXISTS ix_q ON questions(exam_id);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(dbpath()); g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def _close(e):
    d = g.pop("db", None)
    if d: d.close()
def q(sql, a=(), one=False):
    r = db().execute(sql, a).fetchall()
    return (dict(r[0]) if r else None) if one else [dict(x) for x in r]
def x(sql, a=()):
    c = db().execute(sql, a); db().commit(); return c.lastrowid

def log(t, uid=None, eid=None, meta=None, sev="INFO", ts=None):
    ip = request.remote_addr if has_request_context() else None
    ua = (request.user_agent.string or "")[:120] if has_request_context() else None
    x("INSERT INTO audit_logs(user_id,exam_id,type,severity,meta,ip,ua,ts) VALUES(?,?,?,?,?,?,?,?)",
      (uid, eid, t, sev, json.dumps(meta or {}), ip, ua, ts or iso()))
def flag(uid, eid, aid, rule, sev, detail):
    x("INSERT INTO suspicious_events(user_id,exam_id,attempt_id,rule,severity,detail,ts) VALUES(?,?,?,?,?,?,?)", (uid, eid, aid, rule, sev, detail, iso()))
    log("SUSPICIOUS_ACTIVITY", uid, eid, {"rule": rule, "detail": detail}, sev)

def auth(role=None):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = q("SELECT id,name,email,role FROM users WHERE id=?", (session.get("uid"),), True)
            if not u: return jsonify(error="Authentication required"), 401
            if role and u["role"] != role:
                log("UNAUTHORIZED_ACCESS", u["id"], meta={"path": request.path}, sev="MEDIUM")
                return jsonify(error="Forbidden"), 403
            g.user = u; return f(*a, **k)
        return w
    return deco
def pub(u): return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"], "student_id": f"STU{u['id']:04d}"}
def body(): return request.get_json(silent=True) or {}

# ---------------- auth ----------------
@app.post("/api/auth/register")
def register():
    d = body(); name = str(d.get("name", "")).strip()[:80]; em = str(d.get("email", "")).strip().lower(); pw = str(d.get("password", ""))
    if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em): return jsonify(error="Valid name and email required"), 400
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw): return jsonify(error="Password: min 8 chars, letters and digits"), 400
    if q("SELECT 1 FROM users WHERE email=?", (em,), True): return jsonify(error="Email already registered"), 409
    uid = x("INSERT INTO users(name,email,pw,role,created) VALUES(?,?,?,'student',?)", (name, em, generate_password_hash(pw), iso()))
    log("REGISTER", uid); return jsonify(ok=True), 201

@app.post("/api/auth/login")
def login():
    d = body(); em = str(d.get("email", "")).strip().lower(); k = (request.remote_addr, em)
    FAILS[k] = [t for t in FAILS.get(k, []) if time.time() - t < 300]
    if len(FAILS[k]) >= 5:
        log("LOGIN_RATE_LIMITED", meta={"email": em}, sev="HIGH"); return jsonify(error="Too many failed attempts. Try again in 5 minutes."), 429
    u = q("SELECT * FROM users WHERE email=?", (em,), True)
    if not u or not check_password_hash(u["pw"], str(d.get("password", ""))):
        FAILS[k].append(time.time()); log("LOGIN_FAILED", u and u["id"], meta={"email": em}, sev="LOW")
        if u and len(FAILS[k]) >= 3: flag(u["id"], None, None, "MULTIPLE_LOGIN_ATTEMPTS", "MEDIUM", f"{len(FAILS[k])} failed logins within 5 minutes")
        return jsonify(error="Invalid email or password"), 401
    session.clear(); session["uid"] = u["id"]; FAILS.pop(k, None); log("LOGIN", u["id"])
    return jsonify(user=pub(u))

@app.post("/api/auth/logout")
@auth()
def logout():
    log("LOGOUT", g.user["id"]); session.clear(); return jsonify(ok=True)
@app.get("/api/auth/me")
@auth()
def me(): return jsonify(user=pub(g.user))

# ---------------- exams ----------------
def qcheck(d):
    o = {k: str(d.get(k, "")).strip()[:300] for k in ("text", "a", "b", "c", "d")}
    cor = str(d.get("correct", "")).upper()
    try: marks = int(d.get("marks", 1))
    except Exception: marks = 0
    if not all(o.values()) or cor not in "ABCD" or not cor or not 1 <= marks <= 100: return None
    return (o["text"], o["a"], o["b"], o["c"], o["d"], cor, marks)

@app.get("/api/exams")
@auth()
def exams():
    if g.user["role"] == "admin":
        return jsonify(exams=q("SELECT e.*,(SELECT COUNT(*) FROM questions WHERE exam_id=e.id) nq,(SELECT COALESCE(SUM(marks),0) FROM questions WHERE exam_id=e.id) total FROM exams e ORDER BY id DESC"))
    rows = q("""SELECT e.id,e.title,e.description,e.duration_min,(SELECT COUNT(*) FROM questions WHERE exam_id=e.id) nq,
      a.id attempt_id,a.status,a.score,a.total,a.submitted FROM exams e LEFT JOIN attempts a ON a.exam_id=e.id AND a.user_id=? WHERE e.published=1 ORDER BY e.id""", (g.user["id"],))
    return jsonify(exams=rows)

@app.post("/api/exams")
@auth("admin")
def exam_create():
    d = body(); t = str(d.get("title", "")).strip()[:120]
    try: dur = int(d.get("duration_min", 30))
    except Exception: dur = 0
    if not t or not 1 <= dur <= 300: return jsonify(error="Title and duration (1-300 min) required"), 400
    eid = x("INSERT INTO exams(title,description,duration_min,published,created_by) VALUES(?,?,?,0,?)", (t, str(d.get("description", ""))[:500], dur, g.user["id"]))
    log("EXAM_CREATED", g.user["id"], eid); return jsonify(id=eid), 201

@app.get("/api/exams/<int:eid>")
@auth()
def exam_get(eid):
    e = q("SELECT * FROM exams WHERE id=?", (eid,), True)
    if not e or (g.user["role"] != "admin" and not e["published"]): return jsonify(error="Not found"), 404
    e["nq"] = q("SELECT COUNT(*) n FROM questions WHERE exam_id=?", (eid,), True)["n"]
    e["total"] = q("SELECT COALESCE(SUM(marks),0) n FROM questions WHERE exam_id=?", (eid,), True)["n"]
    if g.user["role"] == "admin": e["questions"] = q("SELECT * FROM questions WHERE exam_id=?", (eid,))  # correct answers: admin only
    return jsonify(exam=e)

@app.put("/api/exams/<int:eid>")
@auth("admin")
def exam_update(eid):
    e = q("SELECT * FROM exams WHERE id=?", (eid,), True)
    if not e: return jsonify(error="Not found"), 404
    d = body()
    try: dur = int(d.get("duration_min", e["duration_min"]))
    except Exception: dur = 0
    t = str(d.get("title", e["title"])).strip()[:120]
    if not t or not 1 <= dur <= 300: return jsonify(error="Invalid title/duration"), 400
    pubd = int(bool(d.get("published", e["published"])))
    if pubd and not q("SELECT 1 FROM questions WHERE exam_id=?", (eid,), True): return jsonify(error="Add questions before publishing"), 400
    x("UPDATE exams SET title=?,description=?,duration_min=?,published=? WHERE id=?", (t, str(d.get("description", e["description"]))[:500], dur, pubd, eid))
    log("EXAM_PUBLISHED" if pubd and not e["published"] else "EXAM_UPDATED", g.user["id"], eid); return jsonify(ok=True)

@app.delete("/api/exams/<int:eid>")
@auth("admin")
def exam_delete(eid):
    x("DELETE FROM exams WHERE id=?", (eid,)); log("EXAM_DELETED", g.user["id"], eid, sev="MEDIUM"); return jsonify(ok=True)

@app.post("/api/exams/<int:eid>/questions")
@auth("admin")
def q_add(eid):
    if not q("SELECT 1 FROM exams WHERE id=?", (eid,), True): return jsonify(error="Not found"), 404
    v = qcheck(body())
    if not v: return jsonify(error="Text, 4 options, correct (A-D), marks required"), 400
    qid = x("INSERT INTO questions(exam_id,text,a,b,c,d,correct,marks) VALUES(?,?,?,?,?,?,?,?)", (eid, *v))
    log("QUESTION_ADDED", g.user["id"], eid, {"question_id": qid}); return jsonify(id=qid), 201

@app.put("/api/questions/<int:qid>")
@auth("admin")
def q_edit(qid):
    v = qcheck(body())
    if not v: return jsonify(error="Invalid question"), 400
    x("UPDATE questions SET text=?,a=?,b=?,c=?,d=?,correct=?,marks=? WHERE id=?", (*v, qid)); return jsonify(ok=True)

@app.delete("/api/questions/<int:qid>")
@auth("admin")
def q_del(qid):
    x("DELETE FROM questions WHERE id=?", (qid,)); log("QUESTION_DELETED", g.user["id"], meta={"question_id": qid}); return jsonify(ok=True)

# ---------------- attempts ----------------
@app.post("/api/exams/<int:eid>/start")
@auth("student")
def start(eid):
    e = q("SELECT * FROM exams WHERE id=? AND published=1", (eid,), True)
    if not e: return jsonify(error="Exam not available"), 404
    a = q("SELECT * FROM attempts WHERE user_id=? AND exam_id=?", (g.user["id"], eid), True)
    if a:
        if a["status"] == "submitted": return jsonify(error="You have already attempted this exam"), 409
        log("EXAM_RESUMED", g.user["id"], eid, {"attempt_id": a["id"]}); return jsonify(attempt_id=a["id"])
    ids = [r["id"] for r in q("SELECT id FROM questions WHERE exam_id=?", (eid,))]
    if not ids: return jsonify(error="Exam has no questions"), 400
    random.shuffle(ids); opts = {}
    for i in ids: l = list("ABCD"); random.shuffle(l); opts[str(i)] = l
    n = now(); aid = x("INSERT INTO attempts(user_id,exam_id,started,deadline,order_json,last_seen) VALUES(?,?,?,?,?,?)",
        (g.user["id"], eid, iso(n), iso(n + timedelta(minutes=e["duration_min"])), json.dumps({"q": ids, "o": opts}), iso(n)))
    log("EXAM_STARTED", g.user["id"], eid, {"attempt_id": aid}); return jsonify(attempt_id=aid), 201

def own(aid):
    a = q("SELECT * FROM attempts WHERE id=?", (aid,), True)
    return a if a and a["user_id"] == g.user["id"] else None
def touch(a, net=None):
    x("UPDATE attempts SET last_seen=?,net=COALESCE(?,net) WHERE id=?", (iso(), net, a["id"]))

def grade(a):
    qs = q("SELECT * FROM questions WHERE exam_id=?", (a["exam_id"],))
    ans = {r["question_id"]: r["selected"] for r in q("SELECT * FROM answers WHERE attempt_id=?", (a["id"],))}
    return sum(k["marks"] for k in qs if ans.get(k["id"]) == k["correct"]), sum(k["marks"] for k in qs)
def finish(a, reason):
    s, t = grade(a)
    x("UPDATE attempts SET status='submitted',submitted=?,score=?,total=? WHERE id=?", (iso(), s, t, a["id"]))
    log(reason, a["user_id"], a["exam_id"], {"attempt_id": a["id"], "score": s, "total": t}); return s, t

@app.get("/api/attempts/<int:aid>")
@auth("student")
def attempt_get(aid):
    a = own(aid)
    if not a:
        log("UNAUTHORIZED_ACCESS", g.user["id"], meta={"path": request.path}, sev="MEDIUM"); return jsonify(error="Not found"), 404
    dl = pt(a["deadline"])
    if a["status"] == "in_progress" and now() > dl + timedelta(minutes=15):   # abandoned: auto-submit after long grace
        finish(a, "TIME_EXPIRED"); a = own(aid)
    e = q("SELECT title,duration_min FROM exams WHERE id=?", (a["exam_id"],), True)
    out = {"id": aid, "exam_id": a["exam_id"], "title": e["title"], "status": a["status"], "deadline": a["deadline"], "server_now": iso(),
           "score": a["score"], "total": a["total"], "student": pub(g.user)}
    if a["status"] == "in_progress":
        o = json.loads(a["order_json"]); qs = {r["id"]: r for r in q("SELECT * FROM questions WHERE exam_id=?", (a["exam_id"],))}
        out["questions"] = [{"id": i, "text": qs[i]["text"], "marks": qs[i]["marks"],
                             "options": [{"key": k, "text": qs[i][k.lower()]} for k in o["o"][str(i)]]} for i in o["q"] if i in qs]   # no correct answer sent
        out["answers"] = {str(r["question_id"]): r["selected"] for r in q("SELECT * FROM answers WHERE attempt_id=?", (aid,))}
        touch(a)
    else:
        out["answered"] = q("SELECT COUNT(*) n FROM answers WHERE attempt_id=? AND selected IS NOT NULL", (aid,), True)["n"]
    return jsonify(out)

def save_answers(a, items):
    ok = []; dl = pt(a["deadline"]) + timedelta(seconds=GRACE)
    valid = {r["id"] for r in q("SELECT id FROM questions WHERE exam_id=?", (a["exam_id"],))}
    for it in items[:500]:
        try: qid = int(it.get("question_id"))
        except Exception: continue
        sel = it.get("selected"); ts = it.get("ts") if pt(str(it.get("ts", ""))) else iso()
        if qid not in valid or sel not in (None, "A", "B", "C", "D"): continue
        if pt(ts) > dl: log("LATE_ANSWER_REJECTED", a["user_id"], a["exam_id"], {"question_id": qid}, "MEDIUM"); continue
        if pt(ts) > now() + timedelta(seconds=30): ts = iso()          # clamp forged future timestamps
        cur = q("SELECT updated FROM answers WHERE attempt_id=? AND question_id=?", (a["id"], qid), True)
        if not cur or ts >= cur["updated"]:                            # conflict rule: newest client timestamp wins
            x("INSERT INTO answers(attempt_id,question_id,selected,updated) VALUES(?,?,?,?) ON CONFLICT(attempt_id,question_id) DO UPDATE SET selected=excluded.selected,updated=excluded.updated", (a["id"], qid, sel, ts))
        ok.append(qid)                                                 # acknowledged either way (stale ones are dropped deliberately)
    return ok

EVENTS = {"TAB_SWITCH", "TAB_RETURN", "NETWORK_LOST", "NETWORK_RESTORED", "QUESTION_VIEWED"}
def handle_event(a, ev):
    t = ev.get("type")
    if t not in EVENTS: return
    u, e = a["user_id"], a["exam_id"]
    log(t, u, e, {"attempt_id": a["id"], "client_ts": str(ev.get("ts", ""))[:30]}, "LOW" if t in ("TAB_SWITCH", "NETWORK_LOST") else "INFO")
    if t in ("NETWORK_LOST", "NETWORK_RESTORED"): touch(a, "offline" if t == "NETWORK_LOST" else "online")
    cut = iso(now() - timedelta(seconds=120))
    n = q("SELECT COUNT(*) n FROM audit_logs WHERE user_id=? AND exam_id=? AND type='TAB_SWITCH' AND ts>?", (u, e, cut), True)["n"]
    if t == "TAB_SWITCH" and n == 5: flag(u, e, a["id"], "EXCESSIVE_TAB_SWITCHING", "MEDIUM", "Student switched browser tab 5 times within 2 minutes.")
    if t == "TAB_SWITCH" and n == 8: flag(u, e, a["id"], "EXCESSIVE_TAB_SWITCHING", "HIGH", "Student switched browser tab 8 times within 2 minutes.")
    if t == "NETWORK_LOST":
        c = q("SELECT COUNT(*) n FROM audit_logs WHERE user_id=? AND exam_id=? AND type='NETWORK_LOST' AND ts>?", (u, e, iso(now() - timedelta(minutes=10))), True)["n"]
        if c == 3: flag(u, e, a["id"], "REPEATED_DISCONNECTS", "MEDIUM", "3 connection losses within 10 minutes.")

def live(aid):
    a = own(aid)
    if not a: return None
    return a

@app.post("/api/attempts/<int:aid>/answers")
@auth("student")
def ans(aid):
    a = live(aid)
    if not a: return jsonify(error="Not found"), 404
    if a["status"] != "in_progress": return jsonify(error="Attempt already submitted"), 409
    d = body(); ok = save_answers(a, [{"question_id": d.get("question_id"), "selected": d.get("selected"), "ts": d.get("ts")}]); touch(a)
    if ok: log("ANSWER_SAVED", a["user_id"], a["exam_id"], {"question_id": ok[0]})
    recent = q("SELECT COUNT(*) n FROM audit_logs WHERE user_id=? AND type='ANSWER_SAVED' AND ts>?", (a["user_id"], iso(now() - timedelta(seconds=10))), True)["n"]
    if recent == 15: flag(a["user_id"], a["exam_id"], aid, "RAPID_ANSWER_CHANGES", "LOW", "15 answer changes within 10 seconds.")
    return jsonify(synced=ok)

@app.post("/api/attempts/<int:aid>/sync")
@auth("student")
def sync(aid):
    a = live(aid)
    if not a: return jsonify(error="Not found"), 404
    if a["status"] != "in_progress": return jsonify(error="Attempt already submitted", status=a["status"]), 409
    d = body(); items = d.get("answers") if isinstance(d.get("answers"), list) else []
    evs = d.get("events") if isinstance(d.get("events"), list) else []
    for ev in evs[:100]:
        if isinstance(ev, dict): handle_event(a, ev)
    ok = save_answers(a, [i for i in items if isinstance(i, dict)]); touch(a, "online")
    if ok or evs:
        x("INSERT INTO sync_events(attempt_id,user_id,count,ts) VALUES(?,?,?,?)", (aid, a["user_id"], len(ok), iso()))
        log("ANSWERS_SYNCHRONIZED", a["user_id"], a["exam_id"], {"attempt_id": aid, "answers": len(ok), "events": len(evs)})
    return jsonify(synced=ok, server_now=iso())

@app.post("/api/attempts/<int:aid>/events")
@auth("student")
def events(aid):
    a = live(aid)
    if not a: return jsonify(error="Not found"), 404
    if a["status"] == "in_progress": handle_event(a, body())
    return jsonify(ok=True)

@app.post("/api/attempts/<int:aid>/submit")
@auth("student")
def submit(aid):
    a = live(aid)
    if not a: return jsonify(error="Not found"), 404
    if a["status"] == "submitted": return jsonify(error="Already submitted"), 409
    late = now() > pt(a["deadline"]) + timedelta(seconds=GRACE)
    if late: log("TIME_EXPIRED", a["user_id"], a["exam_id"], {"attempt_id": aid}, "LOW")
    s, t = finish(a, "EXAM_SUBMITTED"); return jsonify(score=s, total=t, late=late)

# ---------------- admin ----------------
@app.get("/api/admin/dashboard")
@auth("admin")
def dash():
    one = lambda s: q(s, (), True)["n"]
    stats = {"students": one("SELECT COUNT(*) n FROM users WHERE role='student'"), "active_exams": one("SELECT COUNT(*) n FROM exams WHERE published=1"),
             "completed": one("SELECT COUNT(*) n FROM attempts WHERE status='submitted'"), "in_progress": one("SELECT COUNT(*) n FROM attempts WHERE status='in_progress'"),
             "avg_pct": round(one("SELECT COALESCE(AVG(100.0*score/NULLIF(total,0)),0) n FROM attempts WHERE status='submitted'"), 1),
             "highest": one("SELECT COALESCE(MAX(score),0) n FROM attempts WHERE status='submitted'"), "lowest": one("SELECT COALESCE(MIN(score),0) n FROM attempts WHERE status='submitted'"),
             "suspicious": one("SELECT COUNT(*) n FROM suspicious_events"), "network_incidents": one("SELECT COUNT(*) n FROM audit_logs WHERE type='NETWORK_LOST'"),
             "syncs": one("SELECT COUNT(*) n FROM sync_events")}
    started = one("SELECT COUNT(*) n FROM attempts"); stats["completion_rate"] = round(100 * stats["completed"] / started, 1) if started else 0
    qs = q("""SELECT substr(k.text,1,60) text, COUNT(*) n, SUM(a.selected=k.correct) c FROM answers a JOIN questions k ON k.id=a.question_id
              JOIN attempts t ON t.id=a.attempt_id AND t.status='submitted' WHERE a.selected IS NOT NULL GROUP BY k.id ORDER BY 1.0*SUM(a.selected=k.correct)/COUNT(*) LIMIT 8""")
    return jsonify(stats=stats, question_perf=[{"text": r["text"], "pct": round(100 * r["c"] / r["n"])} for r in qs])

@app.get("/api/admin/audit-logs")
@auth("admin")
def audit():
    w, a = [], []
    for col, key in (("l.user_id", "user_id"), ("l.exam_id", "exam_id"), ("l.type", "type"), ("l.severity", "severity")):
        if request.args.get(key): w.append(f"{col}=?"); a.append(request.args[key])
    if request.args.get("date"): w.append("l.ts LIKE ?"); a.append(request.args["date"][:10] + "%")
    sql = "SELECT l.*,u.name FROM audit_logs l LEFT JOIN users u ON u.id=l.user_id" + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY l.id DESC LIMIT 300"
    return jsonify(logs=q(sql, a))

@app.get("/api/admin/suspicious-events")
@auth("admin")
def susp():
    return jsonify(events=q("SELECT s.*,u.name,e.title FROM suspicious_events s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN exams e ON e.id=s.exam_id ORDER BY s.id DESC LIMIT 200"))

@app.get("/api/admin/monitoring")
@auth("admin")
def monitor():
    rows = q("""SELECT t.id,u.name,t.user_id,e.title,t.status,t.net,t.last_seen,t.started,t.score,t.total,
      (SELECT COUNT(*) FROM answers WHERE attempt_id=t.id AND selected IS NOT NULL) answered,
      (SELECT COUNT(*) FROM suspicious_events WHERE attempt_id=t.id) flags,
      (SELECT COUNT(*) FROM sync_events WHERE attempt_id=t.id) syncs,
      (SELECT COUNT(*) FROM audit_logs WHERE user_id=t.user_id AND exam_id=t.exam_id AND type='NETWORK_LOST') drops
      FROM attempts t JOIN users u ON u.id=t.user_id JOIN exams e ON e.id=t.exam_id ORDER BY (t.status='in_progress') DESC,t.last_seen DESC""")
    return jsonify(attempts=rows)

@app.get("/api/admin/students")
@auth("admin")
def students():
    rows = q("""SELECT u.id,u.name,u.email,u.created,COUNT(t.id) attempts,COALESCE(MAX(t.score),0) best,
      (SELECT COUNT(*) FROM suspicious_events WHERE user_id=u.id) flags FROM users u LEFT JOIN attempts t ON t.user_id=u.id WHERE u.role='student' GROUP BY u.id""")
    for r in rows: r["student_id"] = f"STU{r['id']:04d}"
    return jsonify(students=rows)

@app.get("/api/student/history")
@auth("student")
def history():
    return jsonify(history=q("SELECT ts,type,severity FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 8", (g.user["id"],)))

@app.errorhandler(404)
def nf(e): return (jsonify(error="Not found"), 404) if request.path.startswith("/api") else send_from_directory(app.static_folder, "index.html")
@app.errorhandler(500)
def er(e): return jsonify(error="Server error"), 500
@app.route("/")
def index(): return send_from_directory(app.static_folder, "index.html")
@app.after_request
def sec(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
                      "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"})
    return r

# ---------------- init + seed (demo data only) ----------------
DEMO_ADMIN_PW, DEMO_STUDENT_PW = "Admin@1234", "Demo@1234"
QS = {"Data Structures Mid-Term (Demo)": (30, [
 ("Which data structure uses LIFO order?", "Queue", "Stack", "Heap", "Graph", "B", 1),
 ("Time complexity of binary search?", "O(n)", "O(n log n)", "O(log n)", "O(1)", "C", 2),
 ("Which traversal uses a queue?", "DFS", "Inorder", "BFS", "Preorder", "C", 1),
 ("Worst case of quicksort?", "O(n^2)", "O(n log n)", "O(n)", "O(log n)", "A", 2),
 ("A complete binary tree with 7 nodes has height?", "1", "2", "3", "4", "B", 1),
 ("Hash table collisions can be resolved by?", "Chaining", "Sorting", "Recursion", "Paging", "A", 1)]),
 "Cyber Security Basics (Demo)": (20, [
 ("Which is a strong password practice?", "Reuse passwords", "Use a password manager", "Share with friends", "Use birthdate", "B", 1),
 ("HTTPS primarily provides?", "Faster pages", "Encryption in transit", "Free hosting", "Ad blocking", "B", 1),
 ("SQL injection is prevented by?", "Parameterized queries", "Longer URLs", "Bigger fonts", "Cookies", "A", 2),
 ("Passwords should be stored as?", "Plain text", "Salted hashes", "Base64", "Comments", "B", 2),
 ("Phishing is?", "A network cable", "Deceptive messages to steal data", "A database", "A firewall", "B", 1),
 ("2FA adds?", "A second verification factor", "More RAM", "A backup", "A proxy", "A", 1)])}

def init_db(seed=True):
    c = sqlite3.connect(dbpath()); c.executescript(SCHEMA); c.commit()
    if seed and not c.execute("SELECT 1 FROM users").fetchone():
        rnd = random.Random(7); t = iso()
        def ins(s, a=()): return c.execute(s, a).lastrowid
        ins("INSERT INTO users(name,email,pw,role,created) VALUES(?,?,?,?,?)", ("Exam Admin", "admin@secureexam.demo", generate_password_hash(DEMO_ADMIN_PW), "admin", t))
        names = ["Aarav Sharma", "Diya Verma", "Kabir Singh", "Meera Joshi", "Rohan Patil", "Ananya Rao", "Ishaan Gupta"]
        sids = [ins("INSERT INTO users(name,email,pw,role,created) VALUES(?,?,?,?,?)", (n, "student@secureexam.demo" if i == 0 else f"student{i+1}@secureexam.demo", generate_password_hash(DEMO_STUDENT_PW), "student", t)) for i, n in enumerate(names)]
        eids = []
        for title, (dur, qs) in QS.items():
            e = ins("INSERT INTO exams(title,description,duration_min,published,created_by) VALUES(?,?,?,?,1)", (title, "Demo examination with randomized questions and options.", dur, 1)); eids.append(e)
            for qq in qs: ins("INSERT INTO questions(exam_id,text,a,b,c,d,correct,marks) VALUES(?,?,?,?,?,?,?,?)", (e, *qq))
        def lg(u, e, ty, sev, meta, mins): ins("INSERT INTO audit_logs(user_id,exam_id,type,severity,meta,ip,ua,ts) VALUES(?,?,?,?,?,?,?,?)", (u, e, ty, sev, json.dumps(meta), "127.0.0.1", "seed", iso(now() - timedelta(minutes=mins))))
        qids = [r[0] for r in c.execute("SELECT id FROM questions WHERE exam_id=?", (eids[0],))]
        for n, u in enumerate(sids[1:5]):   # sample completed attempts on exam 1 (student@ is left free for live demo)
            st = now() - timedelta(hours=3 + n); a = ins("INSERT INTO attempts(user_id,exam_id,started,deadline,submitted,status,order_json,last_seen,net) VALUES(?,?,?,?,?,'submitted',?,?, 'online')", (u, eids[0], iso(st), iso(st + timedelta(minutes=30)), iso(st + timedelta(minutes=22)), json.dumps({"q": qids, "o": {}}), iso(st)))
            for qid in qids:
                cor = c.execute("SELECT correct FROM questions WHERE id=?", (qid,)).fetchone()[0]
                ins("INSERT INTO answers VALUES(?,?,?,?)", (a, qid, cor if rnd.random() < 0.65 else rnd.choice("ABCD"), iso(st)))
            sc = sum(r[1] for r in c.execute("SELECT q.id,q.marks FROM questions q JOIN answers a ON a.question_id=q.id AND a.selected=q.correct WHERE a.attempt_id=?", (a,)))
            c.execute("UPDATE attempts SET score=?,total=8 WHERE id=?", (sc, a))
            lg(u, eids[0], "EXAM_STARTED", "INFO", {"attempt_id": a}, 180 - n * 60); lg(u, eids[0], "EXAM_SUBMITTED", "INFO", {"attempt_id": a, "score": sc}, 160 - n * 60)
            if n == 1:
                lg(u, eids[0], "NETWORK_LOST", "LOW", {"attempt_id": a}, 175); lg(u, eids[0], "NETWORK_RESTORED", "INFO", {"attempt_id": a}, 173)
                lg(u, eids[0], "ANSWERS_SYNCHRONIZED", "INFO", {"attempt_id": a, "answers": 3}, 173); ins("INSERT INTO sync_events(attempt_id,user_id,count,ts) VALUES(?,?,?,?)", (a, u, 3, iso(now() - timedelta(minutes=173))))
            if n == 2:
                ins("INSERT INTO suspicious_events(user_id,exam_id,attempt_id,rule,severity,detail,ts) VALUES(?,?,?,?,?,?,?)", (u, eids[0], a, "EXCESSIVE_TAB_SWITCHING", "HIGH", "Student switched browser tab 8 times within 2 minutes.", iso(now() - timedelta(minutes=115))))
                lg(u, eids[0], "SUSPICIOUS_ACTIVITY", "HIGH", {"rule": "EXCESSIVE_TAB_SWITCHING"}, 115)
        ins("INSERT INTO suspicious_events(user_id,exam_id,attempt_id,rule,severity,detail,ts) VALUES(?,?,?,?,?,?,?)", (sids[5], None, None, "MULTIPLE_LOGIN_ATTEMPTS", "MEDIUM", "4 failed logins within 5 minutes", iso(now() - timedelta(minutes=50))))
        lg(sids[5], None, "LOGIN_FAILED", "LOW", {}, 52)
        c.commit()
    c.close()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    if not os.environ.get("NO_BROWSER"):
        import threading, webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    app.run(host="127.0.0.1", port=port, debug=False)
