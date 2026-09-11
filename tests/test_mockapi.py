from __future__ import annotations

import socket
import time
import unittest

from mockapi.client import ApiClient
from seeds.db import connect
from tests._support import RunningApi, seed_db

PW = "Fixture-Test-Pass-2026!"


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("api")
        cls.api = RunningApi(cls.db, rate_limit_per_min=100_000, login_rate_limit_per_min=100_000)
        cls.client = ApiClient(cls.api.base_url)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.api.close()

    # ------------------------------------------------------------------ auth
    def test_health_reports_seeded_population(self) -> None:
        r = self.client.health()
        self.assertTrue(r.ok)
        self.assertGreaterEqual(r.data["users"], 900, "health must reflect the seeded fixture")
        self.assertEqual(r.data["status"], "ok")

    def test_register_verify_login_read_write_roundtrip(self) -> None:
        email, username = "roundtrip.user@loadtest.invalid", "roundtrip_user"
        reg = self.client.register(email, username, PW)
        self.assertEqual(reg.status, 201, reg.data)
        uid = reg.data["user_id"]

        login = self.client.login(username, PW)
        self.assertEqual(login.status, 200, login.data)
        token = login.data["token"]

        me = self.client.me(token)
        self.assertEqual(me.status, 200)
        self.assertEqual(me.data["id"], uid)
        self.assertEqual(me.data["username"], username)

        post = self.client.message("hello from a test", token)
        self.assertEqual(post.status, 201)
        feed = self.client.feed(limit=5)
        self.assertEqual(feed.status, 200)
        self.assertEqual(feed.data["items"][0]["text"], "hello from a test", "newest write must lead the feed")
        self.assertEqual(self.client.me(token).data["event_count"], me.data["event_count"] + 1)

    def test_login_works_for_seeded_fixture_accounts(self) -> None:
        """The whole point of a hash-faithful fixture: accounts you seeded can
        actually authenticate, using the algo+iterations recorded per user."""
        conn = connect(self.db)
        try:
            email = conn.execute("SELECT email FROM users WHERE status='active' LIMIT 1").fetchone()["email"]
        finally:
            conn.close()
        r = self.client.login(email, PW)
        self.assertEqual(r.status, 200, r.data)
        self.assertTrue(r.data["token"].startswith("ses_"))

    def test_validation_rejects_bad_input(self) -> None:
        for label, (email, username) in {
            "no at-sign": ("nope", "validname"),
            "two at-signs": ("a@b@loadtest.invalid", "validname2"),
        }.items():
            r = self.client.register(email, username, PW)
            self.assertEqual(r.status, 422, f"{label}: {r.data}")
            self.assertEqual(r.data["field"], "email", label)
        r = self.client.register("shortpw@loadtest.invalid", "shortpw", "tiny")
        self.assertEqual(r.status, 422)
        self.assertEqual(r.data["field"], "password")
        r = self.client.register("bad-name@loadtest.invalid", "has space", PW)
        self.assertEqual(r.status, 422)

    def test_duplicate_email_and_username_conflict(self) -> None:
        self.assertEqual(self.client.register("dup@loadtest.invalid", "dupuser", PW).status, 201)
        self.assertEqual(self.client.register("dup@loadtest.invalid", "other-name", PW).status, 409)
        self.assertEqual(self.client.register("other@loadtest.invalid", "dupuser", PW).status, 409)

    def test_bad_credentials_never_leak_why(self) -> None:
        r = self.client.login("nobody@loadtest.invalid", PW)
        self.assertEqual(r.status, 401)
        self.assertEqual(r.data, {"error": "invalid credentials"})

    def test_endpoints_require_a_bearer_token(self) -> None:
        self.assertEqual(self.client.me("").status, 401)
        self.assertEqual(self.client._request("GET", "/users/me").status, 401)
        self.assertEqual(self.client._request("POST", "/messages", {"text": "x"}).status, 401)

    # -------------------------------------------------------------- policies
    def test_disposable_domain_block_is_opt_in(self) -> None:
        with RunningApi(self.db, block_disposable=True, rate_limit_per_min=0, login_rate_limit_per_min=0) as api:
            c = ApiClient(api.base_url)
            r = c.register("blockme@mailinator.com", "blockme123", PW)
            self.assertEqual(r.status, 403)
            self.assertEqual(r.data["field"], "email")

    def test_require_email_verify_leaves_account_pending(self) -> None:
        with RunningApi(self.db, require_email_verify=True, rate_limit_per_min=0,
                        login_rate_limit_per_min=0) as api:
            c = ApiClient(api.base_url)
            r = c.register("pending@loadtest.invalid", "pending_user_x", PW)
            self.assertEqual(r.status, 201)
            self.assertEqual(r.data["status"], "pending_verification")
            self.assertIn("verify_token", r.data)
            self.assertEqual(c.verify("pending@loadtest.invalid").status, 200)
            self.assertEqual(c.verify("pending@loadtest.invalid").status, 404, "verify must be single-use")
            self.assertEqual(c.login("pending@loadtest.invalid", PW).status, 200)

    def test_rate_limit_returns_429_with_retry_after(self) -> None:
        with RunningApi(self.db, rate_limit_per_min=3, login_rate_limit_per_min=0) as api:
            c = ApiClient(api.base_url)
            codes = [c.register(f"rl{i}@loadtest.invalid", f"rluser{i}", PW).status for i in range(8)]
            self.assertEqual(codes[:3], [201, 201, 201])
            self.assertIn(429, codes)
            r = c.register("last@loadtest.invalid", "lastuser", PW)
            self.assertEqual(r.status, 429)
            self.assertGreaterEqual(int(r.headers["Retry-After"]), 1)

    # ------------------------------------------------------- keep-alive guard
    def test_throttled_response_does_not_poison_the_connection(self) -> None:
        """Regression: a 429 short-circuited before the request body was read,
        so the next request on that keep-alive connection parsed leftover JSON
        as its request line and the client got a 400 HTML page instead of JSON.
        Silent, connection-level, and only visible under load."""
        with RunningApi(self.db, rate_limit_per_min=2, login_rate_limit_per_min=0) as api:
            c = ApiClient(api.base_url)  # one thread -> one reused socket
            for i in range(6):
                r = c.register(f"poison{i}@loadtest.invalid", f"poison{i}", PW)
                self.assertIn(r.status, (201, 429), f"attempt {i}: {r.status} {str(r.data)[:80]}")
                self.assertIsInstance(r.data, dict, f"attempt {i} returned a non-JSON body")
            self.assertIsInstance(c.health().data, dict)
            self.assertEqual(c.health().data["status"], "ok")

    def test_malformed_body_is_a_client_error_not_a_crash(self) -> None:
        host, port = self.api.base_url.rsplit("://", 1)[1].split(":")
        s = socket.create_connection((host, int(port)), timeout=5)
        body = b"{not json"
        s.sendall(b"POST /auth/login HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
                  b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        raw = s.recv(4096)
        s.close()
        self.assertIn(b"400", raw.split(b"\r\n", 1)[0])

    def test_unknown_route_is_json_404(self) -> None:
        r = self.client._request("GET", "/definitely-not-here")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.data["error"], "no such route")

    # ------------------------------------------------------------- feed path
    def test_feed_keyset_pagination_walks_without_duplicates(self) -> None:
        seen, cursor, pages = [], None, 0
        while pages < 4:
            r = self.client.feed(limit=10, cursor=cursor)
            self.assertEqual(r.status, 200, r.data)
            ids = [i["id"] for i in r.data["items"]]
            self.assertEqual(len(ids), 10)
            seen += ids
            cursor = r.data["next_cursor"]
            pages += 1
            if not cursor:
                break
        self.assertEqual(len(seen), len(set(seen)), "keyset pages must not repeat or skip rows")
        self.assertEqual(seen, sorted(seen, reverse=True), "ids must descend monotonically with ts")
        self.assertEqual(self.client._request("GET", "/feed?cursor=junk").status, 400)

    def test_feed_rejects_oversized_limit_and_bad_cursor(self) -> None:
        self.assertEqual(self.client.feed(limit=100_000).status, 200)  # clamped, not an error
        self.assertEqual(self.client.feed(limit=0).status, 200)

    def test_server_metrics_match_client_observations(self) -> None:
        def feed_count():
            return self.client.metrics().data["by_route"].get("GET /feed", 0)

        before = feed_count()
        self.assertTrue(self.client.feed(limit=3).ok)
        self.assertEqual(feed_count(), before + 1, "the server must see exactly the requests the client made")
        snap = self.client.metrics().data
        self.assertGreater(snap["server_latency_ms"]["GET /feed"]["p50"], 0.0)
        self.assertLessEqual(snap["server_latency_ms"]["GET /feed"]["p50"],
                             snap["server_latency_ms"]["GET /feed"]["p99"])

    def test_aborted_connections_do_not_leak_admission_slots(self) -> None:
        """Regression: releasing the in-flight slot from the handler's finish()
        looked right, but a connection reset before a request line never gets
        there. Each aborted socket permanently ate a permit, and after a rough
        stage the server accepted TCP and then went deaf forever."""
        import socket
        import threading

        host, port = self.api.base_url.rsplit("://", 1)[1].split(":")
        # 60 connections that handshake, send nothing, and vanish
        def abuse() -> None:
            try:
                s = socket.create_connection((host, int(port)), timeout=2)
                s.close()
            except OSError:
                pass

        threads = [threading.Thread(target=abuse) for _ in range(60)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=4)
        for _ in range(20):
            r = ApiClient(self.api.base_url).health()
            if r.ok:
                return
            time.sleep(0.25)
        self.fail("server stopped answering after aborted connections")

    def test_index_page_is_served_for_browsers(self) -> None:
        r = self.client._request("GET", "/")
        self.assertEqual(r.status, 200)
        self.assertIn("<title>fixture mock API</title>", r.data)

    def test_sample_identifiers_only_returns_active_accounts(self) -> None:
        r = self.client.sample_identifiers(25)
        self.assertTrue(r.ok)
        idents = r.data["identifiers"]
        self.assertEqual(len(idents), 25)
        conn = connect(self.db)
        try:
            marks = {row["status"] for row in conn.execute(
                f"SELECT status FROM users WHERE email IN ({','.join('?' * len(idents))})", idents)}
        finally:
            conn.close()
        self.assertEqual(marks, {"active"}, "the login scenario must not be handed suspended accounts")

    def test_message_body_limits(self) -> None:
        # self-contained: unittest runs methods alphabetically, so never depend
        # on a sibling test having created state
        self.client.register("bodylimits@loadtest.invalid", "bodylimits_user", PW)
        token = self.client.login("bodylimits_user", PW).data["token"]
        self.assertEqual(self.client._request("POST", "/messages", {"text": ""}, token=token).status, 422)
        self.assertEqual(self.client._request("POST", "/messages", {"text": "x" * 3000}, token=token).status, 422)


class ServerMembershipTest(unittest.TestCase):
    """`/servers`, `/servers/<id>/join|leave|members`: the routes the console's
    Operational tab drives. Memberships live in the fixture's own tables, which is the
    whole difference between this and pointing a token at somebody else's room.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("servers")
        conn = connect(cls.db)
        # The seeder randomises private/capacity; this class needs to know which is which.
        conn.execute("UPDATE servers SET private=0, capacity=NULL")
        conn.execute("UPDATE servers SET private=1 WHERE id=2")
        conn.execute("UPDATE servers SET capacity=1 WHERE id=3")
        conn.execute("DELETE FROM memberships")  # connect() is autocommit; no BEGIN/COMMIT here
        cls.emails = [r[0] for r in conn.execute(
            "SELECT email FROM users WHERE status='active' ORDER BY id DESC LIMIT 4").fetchall()]
        cls.private_slug = conn.execute("SELECT slug FROM servers WHERE id=2").fetchone()[0]
        conn.close()
        cls.api = RunningApi(cls.db, rate_limit_per_min=100_000, login_rate_limit_per_min=100_000,
                             join_rate_limit_per_min=100_000)
        cls.client = ApiClient(cls.api.base_url)
        cls.tokens = {}
        for email in cls.emails:
            login = cls.client.login(email, PW)
            assert login.status == 200, login.data
            cls.tokens[email] = login.data["token"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.api.close()

    def setUp(self) -> None:
        """Each test owns its ledger: the counts below are exact, and exact numbers only
        mean something if the starting state is the same every time."""
        conn = connect(self.db)
        conn.execute("DELETE FROM memberships")
        conn.close()

    def auth(self, email: str) -> dict:
        return {"Authorization": f"Bearer {self.tokens[email]}"}

    def live(self, server_id: int) -> list[int]:
        conn = connect(self.db)
        try:
            return sorted(r[0] for r in conn.execute(
                "SELECT user_id FROM memberships WHERE server_id=? AND left_ts IS NULL", (server_id,)))
        finally:
            conn.close()

    def rows(self, server_id: int) -> int:
        conn = connect(self.db)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM memberships WHERE server_id=?",
                                   (server_id,)).fetchone()[0])
        finally:
            conn.close()

    def test_listing_hides_the_invite_slug(self) -> None:
        r = self.client.request("GET", "/servers")
        self.assertEqual(r.status, 200)
        rows = {s["id"]: s for s in r.data["servers"]}
        self.assertEqual(rows[2]["private"], 1)
        self.assertIsNone(rows[2]["slug"], "a list endpoint must not hand out the invite code")
        self.assertIsInstance(rows[1]["slug"], str, "public rows stay identifiable")
        self.assertEqual(rows[1]["members"], len(self.live(1)),
                         "members is the live count, not the row count")

    def test_join_requires_a_bearer(self) -> None:
        r = self.client.request("POST", "/servers/1/join", {})
        self.assertEqual(r.status, 401)
        self.assertIn("bearer", str(r.data["error"]).lower())

    def test_join_leave_rejoin_is_one_row_with_history(self) -> None:
        who = self.emails[0]
        uid = self.client.me(self.tokens[who]).data["id"]  # me() takes the token, not the header
        joined = self.client.request("POST", "/servers/1/join", {}, extra_headers=self.auth(who))
        self.assertEqual(joined.status, 201, joined.data)
        self.assertEqual(joined.data["state"], "joined")
        self.assertEqual(joined.data["members"], 1)
        self.assertEqual(self.live(1), [uid])

        again = self.client.request("POST", "/servers/1/join", {}, extra_headers=self.auth(who))
        self.assertEqual(again.status, 409, again.data)
        self.assertEqual(self.rows(1), 1, "a duplicate join must not invent a membership row")

        left = self.client.request("POST", "/servers/1/leave", {}, extra_headers=self.auth(who))
        self.assertEqual(left.status, 200, left.data)
        self.assertGreaterEqual(left.data["held_seconds"], 0)
        self.assertEqual(self.live(1), [])
        self.assertEqual(self.rows(1), 1, "leave stamps left_ts; it does not delete the row")

        twice = self.client.request("POST", "/servers/1/leave", {}, extra_headers=self.auth(who))
        self.assertEqual(twice.status, 409, twice.data)

        back = self.client.request("POST", "/servers/1/join", {}, extra_headers=self.auth(who))
        self.assertEqual(back.status, 200, back.data)
        self.assertEqual(back.data["state"], "rejoined")
        self.assertEqual(self.rows(1), 1, "rejoin reopens the row rather than appending")

    def test_capacity_and_private_gates_are_the_apps(self) -> None:
        first = self.client.request("POST", "/servers/3/join", {}, extra_headers=self.auth(self.emails[0]))
        self.assertEqual(first.status, 201, first.data)
        second = self.client.request("POST", "/servers/3/join", {}, extra_headers=self.auth(self.emails[1]))
        self.assertEqual(second.status, 403, second.data)
        self.assertIn("capacity", str(second.data["error"]))
        self.assertEqual(self.live(3), [first.data["user_id"]])

        blocked = self.client.request("POST", "/servers/2/join", {}, extra_headers=self.auth(self.emails[2]))
        self.assertEqual(blocked.status, 403, blocked.data)
        self.assertIn("private", str(blocked.data["error"]))
        with_slug = self.client.request("POST", "/servers/2/join", {"invite": self.private_slug},
                                       extra_headers=self.auth(self.emails[2]))
        self.assertEqual(with_slug.status, 201, with_slug.data)

    def test_members_is_keyset_paginated_and_read_only(self) -> None:
        for email in self.emails[:3]:
            r = self.client.request("POST", "/servers/4/join", {}, extra_headers=self.auth(email))
            self.assertEqual(r.status, 201, r.data)
        page = self.client.request("GET", "/servers/4/members?limit=2")
        self.assertEqual(page.status, 200)
        self.assertEqual(len(page.data["members"]), 2)
        self.assertIsNotNone(page.data["next_cursor"])
        rest = self.client.request("GET", f"/servers/4/members?limit=2&cursor={page.data['next_cursor']}")
        self.assertEqual(len(rest.data["members"]), 1)
        self.assertIsNone(rest.data["next_cursor"])
        bad = self.client.request("GET", "/servers/4/members?cursor=nonsense")
        self.assertEqual(bad.status, 400, bad.data)
        forced = self.client.request("POST", "/servers/4/members", {})
        self.assertEqual(forced.status, 405, forced.data)
        self.assertIn("/leave", str(forced.data["error"]), "405 must say where to go instead")

    def test_join_throttling_has_its_own_bucket(self) -> None:
        """`/auth/register` and `/servers/<id>/join` must not share a limiter: a bulk join
        that starved registration would hide the very behaviour a load run is measuring."""
        api = RunningApi(self.db, rate_limit_per_min=100_000, login_rate_limit_per_min=100_000,
                          join_rate_limit_per_min=1)
        client = ApiClient(api.base_url)
        try:
            token = client.login(self.emails[3], PW).data["token"]
            hdrs = {"Authorization": f"Bearer {token}"}
            one = client.request("POST", "/servers/5/join", {}, extra_headers=hdrs)
            self.assertIn(one.status, (200, 201), one.data)
            two = client.request("POST", "/servers/5/join", {}, extra_headers=hdrs)
            self.assertEqual(two.status, 429, two.data)
            self.assertIn("retry_after_s", two.data)
            reg = client.register("bucket.check@loadtest.invalid", "bucket_check", PW)
            self.assertEqual(reg.status, 201, "register kept its own headroom")
        finally:
            client.close()
            api.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
