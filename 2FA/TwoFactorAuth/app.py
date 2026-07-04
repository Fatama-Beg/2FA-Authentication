from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from two_factor_auth import AuthError, TwoFactorAuthSystem

app = Flask(__name__)

# Single in-memory auth system shared by all requests (demo purposes only;
# use a real database and session store in production).
auth_system = TwoFactorAuthSystem()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/register")
def api_register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    email = str(data.get("email", ""))
    password = str(data.get("password", ""))

    try:
        auth_system.register(username, email, password)
    except AuthError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    return jsonify({"ok": True, "message": "Registration successful. You can now log in."})


@app.post("/api/login/step1")
def api_login_step1():
    """Factor 1: verify username + password, then issue an OTP."""

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    try:
        auth_system.login_step1(username, password)
    except AuthError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    # Demo-only: reveal the OTP in the response so this sample app can show
    # it on screen instead of wiring up real email/SMS delivery. A real
    # system would send this out-of-band and never return it to the client.
    demo_otp = auth_system.peek_last_otp(username)
    return jsonify(
        {
            "ok": True,
            "message": "Password verified. A one-time code has been sent to your email.",
            "demo_otp": demo_otp,
            "expires_in": auth_system.seconds_remaining(username),
        }
    )


@app.post("/api/login/step2")
def api_login_step2():
    """Factor 2: verify the one-time code."""

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    otp = str(data.get("otp", ""))

    try:
        auth_system.login_step2(username, otp)
    except AuthError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    return jsonify({"ok": True, "message": "Login successful. Both factors verified."})


if __name__ == "__main__":
    app.run(debug=True)
