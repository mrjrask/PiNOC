"""Coverage for customizable dashboards, saved views, and the Glance page
(pinoc/dashboards.py + the routes/templates it wires into pinoc/web/app.py).

Three layers:

* :class:`CardResolutionTest` / :class:`StorageForecastCardTest` -- pure
  card-data resolution (resolve_card()) against a real PiNOCState, with and
  without a history database;
* :class:`PresetStoreTest` -- the user_presets CRUD (create/list/get/update/
  delete, ownership, invalid input) against a real Database;
* :class:`DashboardsWebTest` -- the HTTP surface through create_app(): auth
  gating, preset save/load round trips, URL-based retrieval, per-owner
  privacy, the live preview endpoint, and the Glance view's rendering
  (default cards, a saved preset's cards, and the absence of navigation
  chrome).
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.dashboards import CARD_TYPES, PresetStore, resolve_card, validate_dashboard_payload, validate_filter_payload
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc


def make_state():
    state = PiNOCState()
    state.publish([DeviceState(
        id="pi", hostname="pi", friendly_name="Pi", online=True, health="warning",
        cpu={"utilization_percent": 55.0, "temperature_c": 61.0},
        memory={"percent": 40.0},
        storage=[{"mount_point": "/data", "percent": 72.0, "total": 100, "used": 72}],
        network={"rx_rate": 1_000, "tx_rate": 2_000},
        uptime_seconds=12_345, last_seen="2024-01-01T00:00:00+00:00",
    )], replace=True)
    state.set_alerts([
        {"device_id": "pi", "state": "active", "severity": "critical", "message": "disk full"},
        {"device_id": "pi", "state": "active", "severity": "warning", "message": "cpu high"},
    ])
    return state


class CardResolutionTest(unittest.TestCase):
    def setUp(self):
        self.state = make_state()

    def test_card_library_covers_every_registered_type(self):
        from pinoc.dashboards import card_library
        types = {c["type"] for c in card_library()}
        self.assertEqual(types, set(CARD_TYPES))

    def test_device_health_card(self):
        rc = resolve_card({"id": "c1", "type": "device_health", "config": {"device_id": "pi"}}, self.state)
        self.assertIsNone(rc["error"])
        self.assertEqual(rc["data"]["friendly_name"], "Pi")
        # The critical alert set via set_alerts() raises health above the
        # device's initial "warning", matching pinoc.state's own health
        # evaluation -- the card must reflect the live, alert-aware value.
        self.assertEqual(rc["data"]["health"], "critical")
        self.assertTrue(rc["data"]["online"])

    def test_device_health_missing_device_errors_without_raising(self):
        rc = resolve_card({"type": "device_health", "config": {"device_id": "nope"}}, self.state)
        self.assertEqual(rc["error"], "device not found")
        self.assertIsNone(rc["data"])

    def test_device_metric_card(self):
        rc = resolve_card({"type": "device_metric", "config": {"device_id": "pi", "metric": "cpu_percent"}}, self.state)
        self.assertEqual(rc["data"]["value"], 55.0)
        rc = resolve_card({"type": "device_metric", "config": {"device_id": "pi", "metric": "disk_percent"}}, self.state)
        self.assertEqual(rc["data"]["value"], 72.0)
        rc = resolve_card({"type": "device_metric", "config": {"device_id": "pi", "metric": "uptime_seconds"}}, self.state)
        self.assertEqual(rc["data"]["value"], 12_345)

    def test_fleet_summary_card(self):
        rc = resolve_card({"type": "fleet_summary", "config": {}}, self.state)
        self.assertEqual(rc["data"]["devices"], 1)
        self.assertEqual(rc["data"]["online"], 1)

    def test_fleet_alert_count_card_filters_by_severity(self):
        rc = resolve_card({"type": "fleet_alert_count", "config": {}}, self.state)
        self.assertEqual(rc["data"]["count"], 2)
        rc = resolve_card({"type": "fleet_alert_count", "config": {"severity": "critical"}}, self.state)
        self.assertEqual(rc["data"]["count"], 1)
        self.assertEqual(rc["data"]["severity"], "critical")

    def test_fleet_aggregate_card(self):
        rc = resolve_card({"type": "fleet_aggregate", "config": {"field": "cpu_average_percent"}}, self.state)
        self.assertEqual(rc["data"]["value"], 55.0)
        rc = resolve_card({"type": "fleet_aggregate", "config": {"field": "cpu_max_temperature_c"}}, self.state)
        self.assertEqual(rc["data"]["value"], 61.0)

    def test_alert_list_card_orders_by_severity_and_respects_limit(self):
        rc = resolve_card({"type": "alert_list", "config": {"limit": 1}}, self.state)
        self.assertEqual(rc["data"]["total"], 2)
        self.assertEqual(len(rc["data"]["alerts"]), 1)
        self.assertEqual(rc["data"]["alerts"][0]["severity"], "critical")

    def test_storage_forecast_card_without_history_is_none(self):
        rc = resolve_card({"type": "storage_forecast", "config": {}}, self.state, history=None)
        self.assertIsNone(rc["error"])
        self.assertIsNone(rc["data"])

    def test_unknown_card_type_errors_without_raising(self):
        rc = resolve_card({"type": "not_a_real_type", "config": {}}, self.state)
        self.assertIsNotNone(rc["error"])
        self.assertIsNone(rc["data"])


class StorageForecastCardTest(unittest.TestCase):
    """The storage_forecast card against a real history database."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {}, None)  # never started; no threads
        self.state = PiNOCState()
        self.state.publish([DeviceState(
            id="pi", hostname="pi", friendly_name="Pi", online=True,
            storage=[{"mount_point": "/data", "percent": 50.0, "total": 1_000_000_000, "used": 500_000_000}],
        )], replace=True)
        now = datetime.now(UTC)
        for i in range(40):
            timestamp = (now - timedelta(hours=39 - i)).isoformat()
            self.db.execute(
                "INSERT OR IGNORE INTO storage_metrics(timestamp,device_id,mount_point,total_bytes,used_bytes) "
                "VALUES(?,?,?,?,?)",
                (timestamp, "pi", "/data", 1_000_000_000, 500_000_000 + i * 10_000_000))

    def tearDown(self):
        self._tmp.cleanup()

    def test_growing_forecast(self):
        rc = resolve_card({"type": "storage_forecast", "config": {}}, self.state, self.history)
        self.assertIsNone(rc["error"])
        self.assertEqual(rc["data"]["status"], "growing")
        self.assertIsNotNone(rc["data"]["estimated_days_remaining"])
        self.assertGreater(rc["data"]["estimated_days_remaining"], 0)


class PayloadValidationTest(unittest.TestCase):
    def test_dashboard_payload_rejects_unknown_card_type(self):
        with self.assertRaises(ValueError):
            validate_dashboard_payload({"cards": [{"type": "not_real"}]})

    def test_dashboard_payload_rejects_non_list_cards(self):
        with self.assertRaises(ValueError):
            validate_dashboard_payload({"cards": "nope"})

    def test_dashboard_payload_clamps_size_and_position(self):
        normalized = validate_dashboard_payload({"cards": [{"type": "fleet_summary", "w": 99, "h": -5}]})
        card = normalized["cards"][0]
        self.assertEqual(card["w"], 6)
        self.assertEqual(card["h"], 1)

    def test_filter_payload_truncates_and_defaults(self):
        normalized = validate_filter_payload({"health": "warning"})
        self.assertEqual(normalized["health"], "warning")
        self.assertEqual(normalized["role"], "")


class PresetStoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.store = PresetStore(self.db)

    def tearDown(self):
        self._tmp.cleanup()

    def test_dashboard_round_trip(self):
        created = self.store.create("alice", "dashboard", "My view", {"cards": [{"type": "fleet_summary"}]})
        self.assertEqual(created["name"], "My view")
        self.assertEqual(created["payload"]["cards"][0]["type"], "fleet_summary")
        fetched = self.store.get(created["preset_id"])
        self.assertEqual(fetched, created)
        listed = self.store.list("alice", "dashboard")
        self.assertEqual([x["preset_id"] for x in listed], [created["preset_id"]])

    def test_update_and_delete_require_matching_owner(self):
        created = self.store.create("alice", "dashboard", "V1", {"cards": []})
        updated = self.store.update(created["preset_id"], "alice", name="V2",
                                     payload={"cards": [{"type": "fleet_summary"}]})
        self.assertEqual(updated["name"], "V2")
        self.assertEqual(len(updated["payload"]["cards"]), 1)
        self.assertIsNone(self.store.update(created["preset_id"], "bob", name="hijacked"))
        self.assertFalse(self.store.delete(created["preset_id"], "bob"))
        self.assertTrue(self.store.delete(created["preset_id"], "alice"))
        self.assertIsNone(self.store.get(created["preset_id"]))

    def test_fleet_filter_round_trip(self):
        created = self.store.create("alice", "fleet_filter", "VPN devices",
                                     {"role": "vpn_server", "health": "warning"})
        self.assertEqual(created["payload"]["role"], "vpn_server")
        self.assertEqual(created["payload"]["health"], "warning")
        fetched = self.store.list("alice", "fleet_filter")
        self.assertEqual(len(fetched), 1)

    def test_invalid_kind_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create("alice", "bogus", "name", {})

    def test_empty_name_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create("alice", "dashboard", "  ", {"cards": []})

    def test_presets_are_scoped_by_owner(self):
        self.store.create("alice", "dashboard", "Alice's", {"cards": []})
        self.store.create("bob", "dashboard", "Bob's", {"cards": []})
        self.assertEqual(len(self.store.list("alice", "dashboard")), 1)
        self.assertEqual(len(self.store.list("bob", "dashboard")), 1)


class DashboardsWebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {})
        self.state = make_state()
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True,
                         "SECRET_KEY": "test-secret", "DATABASE": self.db},
            self.history, None)
        self.security = self.app.extensions["pinoc_security"]
        self.security.create_user("alice", "pw1234567890", "viewer")
        self.security.create_user("bob", "pw1234567890", "viewer")
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def _login(self, username, password="pw1234567890"):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post("/login", data={"username": username, "password": password, "csrf_token": csrf})

    def _logout(self):
        self.client.post("/logout", headers={"X-CSRF-Token": self._csrf()})

    def _csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _post(self, path, body=None):
        return self.client.post(path, json=body or {}, headers={"X-CSRF-Token": self._csrf()})

    def _put(self, path, body=None):
        return self.client.put(path, json=body or {}, headers={"X-CSRF-Token": self._csrf()})

    def _delete(self, path):
        return self.client.delete(path, headers={"X-CSRF-Token": self._csrf()})

    # -- auth gating ---------------------------------------------------
    def test_unauthenticated_api_requests_are_rejected(self):
        self.assertEqual(self.client.get("/api/dashboards").status_code, 401)
        self.assertEqual(self.client.get("/api/card-library").status_code, 401)
        self.assertEqual(self.client.get("/api/fleet-filters").status_code, 401)

    # -- card library ----------------------------------------------------
    def test_card_library_lists_every_type(self):
        self._login("alice")
        response = self.client.get("/api/card-library")
        self.assertEqual(response.status_code, 200)
        types = {c["type"] for c in response.get_json()["cards"]}
        self.assertEqual(types, set(CARD_TYPES))

    # -- dashboard preset CRUD + save/load round trip ---------------------
    def test_create_list_get_update_delete_round_trip(self):
        self._login("alice")
        created = self._post("/api/dashboards", {"name": "Home", "payload": {"cards": [{"type": "fleet_summary"}]}})
        self.assertEqual(created.status_code, 201)
        preset_id = created.get_json()["dashboard"]["preset_id"]

        listing = self.client.get("/api/dashboards")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.get_json()["dashboards"]), 1)

        detail = self.client.get(f"/api/dashboards/{preset_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["dashboard"]["name"], "Home")

        updated = self._put(f"/api/dashboards/{preset_id}", {"name": "Home v2"})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["dashboard"]["name"], "Home v2")

        deleted = self._delete(f"/api/dashboards/{preset_id}")
        self.assertTrue(deleted.get_json()["ok"])
        self.assertEqual(self.client.get(f"/api/dashboards/{preset_id}").status_code, 404)

    def test_dashboard_data_resolves_saved_cards(self):
        self._login("alice")
        created = self._post("/api/dashboards", {
            "name": "Home",
            "payload": {"cards": [{"type": "device_health", "config": {"device_id": "pi"}}]},
        })
        preset_id = created.get_json()["dashboard"]["preset_id"]
        data = self.client.get(f"/api/dashboards/{preset_id}/data")
        self.assertEqual(data.status_code, 200)
        cards = data.get_json()["cards"]
        self.assertEqual(len(cards), 1)
        self.assertIsNone(cards[0]["error"])
        self.assertEqual(cards[0]["data"]["device_id"], "pi")

    def test_dashboard_is_private_to_its_owner(self):
        self._login("alice")
        created = self._post("/api/dashboards", {"name": "Alice's", "payload": {"cards": []}})
        preset_id = created.get_json()["dashboard"]["preset_id"]
        self._logout()
        self._login("bob")
        self.assertEqual(self.client.get(f"/api/dashboards/{preset_id}").status_code, 404)
        self.assertEqual(self.client.get(f"/api/dashboards/{preset_id}/data").status_code, 404)
        self.assertEqual(self._put(f"/api/dashboards/{preset_id}", {"name": "hijacked"}).status_code, 404)
        # Bob's own list stays empty -- Alice's dashboard never appears in it.
        self.assertEqual(self.client.get("/api/dashboards").get_json()["dashboards"], [])

    # -- URL-based preset retrieval (the "shareable URL") -----------------
    def test_dashboard_view_page_and_url_load_the_saved_preset(self):
        self._login("alice")
        created = self._post("/api/dashboards", {"name": "Home", "payload": {"cards": [{"type": "fleet_summary"}]}})
        preset_id = created.get_json()["dashboard"]["preset_id"]
        page = self.client.get(f"/dashboards/{preset_id}")
        self.assertEqual(page.status_code, 200)
        self.assertIn(preset_id.encode(), page.data)
        list_page = self.client.get("/dashboards")
        self.assertEqual(list_page.status_code, 200)

    # -- the composer's live preview never persists anything --------------
    def test_preview_resolves_without_saving(self):
        self._login("alice")
        response = self._post("/api/dashboards/preview", {"cards": [{"type": "fleet_alert_count", "config": {}}]})
        self.assertEqual(response.status_code, 200)
        cards = response.get_json()["cards"]
        self.assertEqual(cards[0]["type"], "fleet_alert_count")
        self.assertEqual(cards[0]["data"]["count"], 2)
        self.assertEqual(self.client.get("/api/dashboards").get_json()["dashboards"], [])

    # -- saved fleet-filter presets ---------------------------------------
    def test_fleet_filter_preset_save_and_load_round_trip(self):
        self._login("alice")
        created = self._post("/api/fleet-filters", {"name": "Critical only", "payload": {"health": "critical"}})
        self.assertEqual(created.status_code, 201)
        preset_id = created.get_json()["filter"]["preset_id"]
        listing = self.client.get("/api/fleet-filters")
        self.assertEqual(len(listing.get_json()["filters"]), 1)
        self.assertEqual(listing.get_json()["filters"][0]["payload"]["health"], "critical")
        updated = self._put(f"/api/fleet-filters/{preset_id}", {"payload": {"health": "warning"}})
        self.assertEqual(updated.get_json()["filter"]["payload"]["health"], "warning")
        deleted = self._delete(f"/api/fleet-filters/{preset_id}")
        self.assertTrue(deleted.get_json()["ok"])
        self.assertEqual(self.client.get("/api/fleet-filters").get_json()["filters"], [])

    # -- Glance view --------------------------------------------------------
    def test_glance_page_has_no_navigation_chrome(self):
        self._login("alice")
        page = self.client.get("/glance")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(b"Primary navigation", page.data)
        self.assertNotIn(b"site-header", page.data)
        self.assertNotIn(b"Fleet</a>", page.data)

    def test_glance_default_cards_when_no_preset(self):
        self._login("alice")
        response = self.client.get("/api/glance")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        types = [c["type"] for c in payload["cards"]]
        self.assertIn("fleet_summary", types)
        self.assertIn("fleet_alert_count", types)
        self.assertIn("device_health", types)  # the one published device

    def test_glance_renders_a_saved_preset_by_url(self):
        self._login("alice")
        created = self._post("/api/dashboards", {
            "name": "Kiosk", "payload": {"cards": [{"type": "fleet_alert_count", "config": {}}]},
        })
        preset_id = created.get_json()["dashboard"]["preset_id"]
        page = self.client.get(f"/glance?preset={preset_id}")
        self.assertEqual(page.status_code, 200)
        api = self.client.get(f"/api/glance?preset={preset_id}")
        self.assertEqual(api.status_code, 200)
        payload = api.get_json()
        self.assertEqual(payload["name"], "Kiosk")
        self.assertEqual(len(payload["cards"]), 1)
        self.assertEqual(payload["cards"][0]["type"], "fleet_alert_count")

    def test_glance_falls_back_to_default_for_another_users_preset(self):
        self._login("alice")
        created = self._post("/api/dashboards", {"name": "Alice's", "payload": {"cards": [{"type": "fleet_summary"}]}})
        preset_id = created.get_json()["dashboard"]["preset_id"]
        self._logout()
        self._login("bob")
        response = self.client.get(f"/api/glance?preset={preset_id}")
        self.assertEqual(response.status_code, 200)
        # Bob doesn't own Alice's preset, so Glance quietly falls back to the
        # default cards rather than leaking her layout to him.
        self.assertEqual(response.get_json()["name"], "Glance")


if __name__ == "__main__":
    unittest.main()
