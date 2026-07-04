import unittest

from app import app, auth_system


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        # Reset shared in-memory state between tests.
        auth_system.users.clear()
        auth_system._pending.clear()
        auth_system._last_sent_otp.clear()

    def test_index_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Two-Factor Authentication", response.data)

    def test_register_then_login_flow(self):
        reg_response = self.client.post(
            "/api/register",
            json={"username": "alice", "email": "alice@example.com", "password": "GoodPass123"},
        )
        self.assertEqual(reg_response.status_code, 200)
        self.assertTrue(reg_response.get_json()["ok"])

        step1_response = self.client.post(
            "/api/login/step1", json={"username": "alice", "password": "GoodPass123"}
        )
        self.assertEqual(step1_response.status_code, 200)
        step1_data = step1_response.get_json()
        self.assertTrue(step1_data["ok"])
        otp = step1_data["demo_otp"]
        self.assertEqual(len(otp), 6)

        step2_response = self.client.post(
            "/api/login/step2", json={"username": "alice", "otp": otp}
        )
        self.assertEqual(step2_response.status_code, 200)
        self.assertTrue(step2_response.get_json()["ok"])

    def test_login_step1_rejects_bad_password(self):
        self.client.post(
            "/api/register",
            json={"username": "bob", "email": "bob@example.com", "password": "GoodPass123"},
        )
        response = self.client.post(
            "/api/login/step1", json={"username": "bob", "password": "WrongPass"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_login_step2_rejects_bad_otp(self):
        self.client.post(
            "/api/register",
            json={"username": "carol", "email": "carol@example.com", "password": "GoodPass123"},
        )
        self.client.post(
            "/api/login/step1", json={"username": "carol", "password": "GoodPass123"}
        )
        response = self.client.post(
            "/api/login/step2", json={"username": "carol", "otp": "000000"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])


if __name__ == "__main__":
    unittest.main()
