"""Run: python -m unittest discover -s tests -v   (no extra dependencies)"""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app as A

def login(c, e, p): return c.post("/api/auth/login", json={"email": e, "password": p})
def cl(e, p):
    A.FAILS.clear()
    c = A.app.test_client(); assert login(c, e, p).status_code == 200; return c
S = lambda: cl("student@secureexam.demo", "Demo@1234")
AD = lambda: cl("admin@secureexam.demo", "Admin@1234")
Q = lambda t="Q", cor="A": {"text": t, "a": "a", "b": "b", "c": "c", "d": "d", "correct": cor, "marks": 1}

class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls): A.init_db()
    def test_register_login_hash(self):
        c = A.app.test_client(); r = "/api/auth/register"
        self.assertEqual(c.post(r, json={"name": "T", "email": "t@x.io", "password": "weak"}).status_code, 400)
        self.assertEqual(c.post(r, json={"name": "T", "email": "t@x.io", "password": "Passw0rd1"}).status_code, 201)
        self.assertEqual(c.post(r, json={"name": "T", "email": "t@x.io", "password": "Passw0rd1"}).status_code, 409)
        self.assertEqual(login(c, "t@x.io", "bad").status_code, 401)
        with A.app.app_context(): self.assertNotEqual(A.q("SELECT pw FROM users WHERE email='t@x.io'", (), True)["pw"], "Passw0rd1")
    def test_unauthorized_rbac(self):
        self.assertEqual(A.app.test_client().get("/api/exams").status_code, 401)
        s = S(); self.assertEqual(s.get("/api/admin/dashboard").status_code, 403); self.assertEqual(s.post("/api/exams", json={"title": "x"}).status_code, 403)
        self.assertEqual(AD().post("/api/exams/1/start").status_code, 403)
        self.assertTrue(AD().get("/api/admin/audit-logs?type=UNAUTHORIZED_ACCESS").get_json()["logs"])
    def test_exam_create_get(self):
        a = AD(); eid = a.post("/api/exams", json={"title": "T", "duration_min": 10}).get_json()["id"]
        self.assertEqual(a.put(f"/api/exams/{eid}", json={"published": 1}).status_code, 400)
        self.assertEqual(a.post(f"/api/exams/{eid}/questions", json=Q()).status_code, 201)
        self.assertEqual(a.put(f"/api/exams/{eid}", json={"published": 1}).status_code, 200)
        self.assertEqual(a.get(f"/api/exams/{eid}").get_json()["exam"]["nq"], 1)
        self.assertTrue(any(e["id"] == eid for e in S().get("/api/exams").get_json()["exams"]))
    def test_attempt_offline_sync_submit(self):
        a = AD(); eid = a.post("/api/exams", json={"title": "F", "duration_min": 10}).get_json()["id"]
        for i in range(3): a.post(f"/api/exams/{eid}/questions", json=Q(f"Q{i}"))
        a.put(f"/api/exams/{eid}", json={"published": 1})
        s = cl("student3@secureexam.demo", "Demo@1234"); aid = s.post(f"/api/exams/{eid}/start").get_json()["attempt_id"]
        d = s.get(f"/api/attempts/{aid}").get_json(); self.assertNotIn("correct", str(d)); ids = [q["id"] for q in d["questions"]]
        self.assertEqual(s.post(f"/api/attempts/{aid}/answers", json={"question_id": ids[0], "selected": "A", "ts": A.iso()}).status_code, 200)
        ts = A.iso()
        r = s.post(f"/api/attempts/{aid}/sync", json={"answers": [{"question_id": ids[1], "selected": "A", "ts": ts}, {"question_id": ids[2], "selected": "B", "ts": ts}, {"question_id": 99999, "selected": "A", "ts": ts}],
            "events": [{"type": "NETWORK_LOST", "ts": ts}, {"type": "NETWORK_RESTORED", "ts": ts}]}).get_json()
        self.assertEqual(sorted(r["synced"]), sorted(ids[1:]))
        old = s.post(f"/api/attempts/{aid}/sync", json={"answers": [{"question_id": ids[1], "selected": "C", "ts": "2000-01-01T00:00:00.000Z"}]}).get_json()
        self.assertEqual(old["synced"], [ids[1]])                       # stale write acknowledged, not applied
        r = s.post(f"/api/attempts/{aid}/submit").get_json(); self.assertEqual((r["score"], r["total"]), (2, 3))
        self.assertEqual(s.post(f"/api/attempts/{aid}/submit").status_code, 409)
        self.assertEqual(s.post(f"/api/attempts/{aid}/sync", json={"answers": []}).status_code, 409)
        for t in ("NETWORK_LOST", "ANSWERS_SYNCHRONIZED", "EXAM_SUBMITTED"): self.assertTrue(AD().get(f"/api/admin/audit-logs?type={t}").get_json()["logs"], t)
    def test_isolation_and_detection_and_ratelimit(self):
        s = S(); self.assertEqual(s.get("/api/attempts/1").status_code, 404)
        aid = s.post("/api/exams/2/start").get_json()["attempt_id"]
        for _ in range(8): s.post(f"/api/attempts/{aid}/events", json={"type": "TAB_SWITCH"})
        ev = AD().get("/api/admin/suspicious-events").get_json()["events"]
        self.assertTrue({"MEDIUM", "HIGH"} <= {e["severity"] for e in ev if e["rule"] == "EXCESSIVE_TAB_SWITCHING" and e["attempt_id"] == aid})
        c = A.app.test_client(); codes = [login(c, "admin@secureexam.demo", "nope").status_code for _ in range(6)]; self.assertEqual(codes[-1], 429)
if __name__ == "__main__": unittest.main()
