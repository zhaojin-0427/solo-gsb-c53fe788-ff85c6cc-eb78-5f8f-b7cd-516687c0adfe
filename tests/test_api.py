"""Integration tests for the HTTP API.

Require: pip install -r requirements.txt httpx, and a reachable PostgreSQL
(set TEST_DATABASE_URL). They run automatically inside docker-compose based
CI; locally they are skipped when dependencies or the DB are unavailable.
"""
import os
import threading
import unittest

try:
    from fastapi.testclient import TestClient

    from app.config import get_settings
    from app.db import Base, get_engine
    from app.main import app

    _IMPORTS_OK = True
except Exception:  # pragma: no cover - deps not installed
    _IMPORTS_OK = False


def _db_available() -> bool:
    if not _IMPORTS_OK:
        return False
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        os.environ["DATABASE_URL"] = url
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_db_available(), "FastAPI deps or test database unavailable")
class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine = get_engine()
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        cls.client = TestClient(app)

    def setUp(self):
        engine = get_engine()
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

    # -- helpers ---------------------------------------------------------
    def create_policy(self, name="pii", rules=None):
        rules = rules if rules is not None else [
            {"id": "r1", "path": "$.users[*].ssn", "action": "tokenize"},
            {"id": "r2", "path": "$.users[*].name", "action": "mask",
             "params": {"keep_first": 1}},
            {"id": "r3", "path": "$.debug", "action": "delete"},
        ]
        resp = self.client.post("/v1/policies", json={"name": name, "rules": rules})
        assert resp.status_code == 201, resp.text
        return resp

    def publish(self, name="pii", expected_revision=0):
        resp = self.client.post(
            f"/v1/policies/{name}/publish",
            json={"expected_revision": expected_revision},
        )
        return resp

    # -- policy lifecycle ------------------------------------------------
    def test_policy_lifecycle_and_cas(self):
        self.create_policy()
        # publish with wrong expected revision -> 409
        resp = self.publish(expected_revision=5)
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()["error"]["code"], "REVISION_CONFLICT")
        # correct CAS
        resp = self.publish(expected_revision=0)
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["version"], 1)
        # replaying the same CAS now fails (revision moved on)
        resp = self.publish(expected_revision=0)
        self.assertEqual(resp.status_code, 409)
        # published version is immutable and retrievable
        resp = self.client.get("/v1/policies/pii/versions/1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()["rules"]), 3)
        # draft can change without touching the published version
        resp = self.client.put(
            "/v1/policies/pii/draft",
            json={"rules": [{"id": "r9", "path": "$.x", "action": "delete"}]},
        )
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get("/v1/policies/pii/versions/1")
        self.assertEqual(len(resp.json()["rules"]), 3)
        resp = self.publish(expected_revision=1)
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["version"], 2)

    def test_invalid_rules_rejected(self):
        resp = self.client.post(
            "/v1/policies",
            json={"name": "bad", "rules": [{"id": "r1", "path": "users", "action": "delete"}]},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.json()["error"]["code"], "INVALID_RULES")

    # -- transform -------------------------------------------------------
    def doc(self):
        return {
            "users": [
                {"name": "ann", "ssn": "111-22-3333"},
                {"name": "bob", "ssn": "444-55-6666"},
            ],
            "debug": {"trace": True},
        }

    def test_transform_and_replay(self):
        self.create_policy()
        self.publish(expected_revision=0)
        payload = {"version": 1, "idempotency_key": "k-1", "document": self.doc()}
        resp = self.client.post("/v1/policies/pii/transform", json=payload)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["replayed"])
        self.assertEqual(body["version"], 1)
        result = body["result"]
        self.assertNotIn("debug", result)
        self.assertTrue(result["users"][0]["ssn"].startswith("tok_"))
        self.assertEqual(result["users"][0]["name"], "a**")
        statuses = {(t["rule_id"], t["path"]): t["status"] for t in body["trace"]}
        self.assertEqual(statuses[("r3", "$.debug")], "applied")

        # same key + same document -> replay, identical result
        resp2 = self.client.post("/v1/policies/pii/transform", json=payload)
        self.assertEqual(resp2.status_code, 200)
        body2 = resp2.json()
        self.assertTrue(body2["replayed"])
        self.assertEqual(body2["result"], body["result"])
        self.assertEqual(body2["trace"], body["trace"])

        # same key + different document -> 409
        payload2 = dict(payload, document={"users": [], "debug": None})
        resp3 = self.client.post("/v1/policies/pii/transform", json=payload2)
        self.assertEqual(resp3.status_code, 409)
        self.assertEqual(resp3.json()["error"]["code"], "IDEMPOTENCY_KEY_CONFLICT")

        # same key is scoped to the version: publish v2, key is reusable there
        self.publish(expected_revision=1)
        payload3 = dict(payload, version=2)
        resp4 = self.client.post("/v1/policies/pii/transform", json=payload3)
        self.assertEqual(resp4.status_code, 200)
        self.assertFalse(resp4.json()["replayed"])

    def test_concurrent_same_key_executes_once(self):
        self.create_policy()
        self.publish(expected_revision=0)
        payload = {"version": 1, "idempotency_key": "k-conc", "document": self.doc()}
        results = []

        def worker():
            client = TestClient(app)  # per-thread client for real concurrency
            r = client.post("/v1/policies/pii/transform", json=payload)
            results.append((r.status_code, r.json()))

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(s == 200 for s, _ in results))
        replays = [b["replayed"] for _, b in results]
        self.assertEqual(replays.count(False), 1)  # exactly one execution
        first_result = results[0][1]["result"]
        for _, b in results:
            self.assertEqual(b["result"], first_result)  # identical results
        # exactly one audit row for the successful execution
        engine = get_engine()
        with engine.connect() as conn:
            rows = conn.exec_driver_sql(
                "SELECT COUNT(*) FROM audit_events WHERE outcome = 'success'"
            ).scalar()
        self.assertEqual(rows, 1)

    def test_transform_requires_version_and_key(self):
        self.create_policy()
        self.publish(expected_revision=0)
        resp = self.client.post(
            "/v1/policies/pii/transform", json={"document": self.doc()}
        )
        self.assertEqual(resp.status_code, 422)
        resp = self.client.post(
            "/v1/policies/pii/transform",
            json={"version": 1, "document": self.doc()},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.json()["error"]["code"], "VALIDATION_FAILED")

    def test_error_response_contains_no_values(self):
        self.create_policy()
        self.publish(expected_revision=0)
        secret = "super-secret-value-123"
        resp = self.client.post(
            "/v1/policies/pii/transform",
            json={"version": 99, "idempotency_key": "k", "document": {"leak": secret}},
        )
        self.assertEqual(resp.status_code, 404)
        self.assertNotIn(secret, resp.text)


if __name__ == "__main__":
    unittest.main()
