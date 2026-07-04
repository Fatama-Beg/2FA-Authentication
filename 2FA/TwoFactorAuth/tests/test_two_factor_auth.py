import time
import unittest

from two_factor_auth import AuthError, MAX_OTP_ATTEMPTS, OTP_VALIDITY_SECONDS, TwoFactorAuthSystem


class TwoFactorAuthTests(unittest.TestCase):
    def setUp(self):
        self.system = TwoFactorAuthSystem()
        self.system.register("jane_doe", "jane@example.com", "S3curePass!")

    def test_registration_rejects_duplicate_username(self):
        with self.assertRaises(AuthError):
            self.system.register("jane_doe", "other@example.com", "AnotherPass1")

    def test_registration_rejects_invalid_email(self):
        with self.assertRaises(AuthError):
            self.system.register("bob", "not-an-email", "SomePass123")

    def test_registration_rejects_short_password(self):
        with self.assertRaises(AuthError):
            self.system.register("bob", "bob@example.com", "short")

    def test_login_step1_rejects_wrong_password(self):
        with self.assertRaises(AuthError):
            self.system.login_step1("jane_doe", "wrong-password")

    def test_login_step1_rejects_unknown_user(self):
        with self.assertRaises(AuthError):
            self.system.login_step1("ghost", "whatever")

    def test_full_login_flow_succeeds_with_correct_otp(self):
        otp = self.system.login_step1("jane_doe", "S3curePass!")
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

        result = self.system.login_step2("jane_doe", otp)
        self.assertTrue(result)

    def test_otp_is_single_use(self):
        otp = self.system.login_step1("jane_doe", "S3curePass!")
        self.system.login_step2("jane_doe", otp)

        with self.assertRaises(AuthError):
            self.system.login_step2("jane_doe", otp)

    def test_wrong_otp_is_rejected(self):
        self.system.login_step1("jane_doe", "S3curePass!")
        with self.assertRaises(AuthError):
            self.system.login_step2("jane_doe", "000000")

    def test_too_many_attempts_locks_challenge(self):
        self.system.login_step1("jane_doe", "S3curePass!")
        for _ in range(MAX_OTP_ATTEMPTS - 1):
            with self.assertRaises(AuthError):
                self.system.login_step2("jane_doe", "000000")

        with self.assertRaises(AuthError):
            self.system.login_step2("jane_doe", "000000")

        # Even the correct OTP should no longer work after lockout, since
        # the whole challenge is discarded once attempts are exhausted.
        real_otp = self.system.login_step1("jane_doe", "S3curePass!")
        self.assertTrue(self.system.login_step2("jane_doe", real_otp))

    def test_expired_otp_is_rejected(self):
        otp = self.system.login_step1("jane_doe", "S3curePass!")
        challenge = self.system._pending["jane_doe"]
        challenge.created_at = time.time() - (OTP_VALIDITY_SECONDS + 5)

        with self.assertRaises(AuthError):
            self.system.login_step2("jane_doe", otp)


if __name__ == "__main__":
    unittest.main()
