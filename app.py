from flask import Flask, render_template, request, redirect, url_for
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock

app = Flask(__name__)

# Dummy accounts for local testing only
DEMO_ACCOUNTS = {
    "admin": "DemoAdmin123!",
    "student": "DemoStudent123!"
}

MAX_FAILURES = 5
WINDOW_SECONDS = 60
BLOCK_SECONDS = 60

failed_attempts = defaultdict(deque)
blocked_until = {}

events = deque(maxlen=100)
alerts = deque(maxlen=50)

lock = Lock()


def add_event(username, status, message):
    events.appendleft({
        "time": datetime.now().strftime("%H:%M:%S"),
        "username": username,
        "status": status,
        "message": message
    })


def check_login(username, password):
    now = datetime.now()

    with lock:
        # Check temporary account lockout
        if username in blocked_until:
            if now < blocked_until[username]:
                remaining = int(
                    (blocked_until[username] - now).total_seconds()
                ) + 1

                add_event(
                    username,
                    "BLOCKED",
                    "Login attempted during temporary lockout"
                )

                return False, (
                    f"Account temporarily blocked. "
                    f"Try again in {remaining} seconds."
                )

            del blocked_until[username]
            failed_attempts[username].clear()

        attempts = failed_attempts[username]

        # Remove attempts older than the detection window
        while attempts and (
            now - attempts[0]
        ).total_seconds() > WINDOW_SECONDS:
            attempts.popleft()

        # Verify demo credentials
        if DEMO_ACCOUNTS.get(username) == password:
            failed_attempts[username].clear()

            add_event(
                username,
                "SUCCESS",
                "Successful demo login"
            )

            return True, "Login successful!"

        # Record a failed attempt
        attempts.append(now)

        add_event(
            username,
            "FAILED",
            f"Failed attempt number {len(attempts)}"
        )

        # Detect repeated failures
        if len(attempts) >= MAX_FAILURES:
            blocked_until[username] = (
                now + timedelta(seconds=BLOCK_SECONDS)
            )

            alerts.appendleft({
                "time": now.strftime("%H:%M:%S"),
                "username": username,
                "message": (
                    f"Brute-force pattern detected: "
                    f"{len(attempts)} failed attempts "
                    f"within {WINDOW_SECONDS} seconds."
                )
            })

            add_event(
                username,
                "ALERT",
                "Repeated failures detected"
            )

            return False, (
                "SECURITY ALERT: Repeated failed login attempts "
                "detected. The demo account is temporarily blocked."
            )

        remaining = MAX_FAILURES - len(attempts)

        return False, (
            f"Invalid credentials. {remaining} attempt(s) "
            f"remaining before an alert."
        )


@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    message_type = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            message = "Please enter your username and password."
            message_type = "error"

        elif len(username) > 50 or len(password) > 200:
            message = "Input is too long."
            message_type = "error"

        else:
            success, message = check_login(username, password)

            message_type = "success" if success else "error"

    with lock:
        event_list = list(events)
        alert_list = list(alerts)

    return render_template(
        "index.html",
        message=message,
        message_type=message_type,
        events=event_list,
        alerts=alert_list,
        max_failures=MAX_FAILURES,
        window_seconds=WINDOW_SECONDS
    )


@app.route("/reset", methods=["POST"])
def reset():
    with lock:
        failed_attempts.clear()
        blocked_until.clear()
        events.clear()
        alerts.clear()

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)