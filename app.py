"""SecureX - Password Strength Analyzer server.

Run with:  python3 app.py
Then open: http://127.0.0.1:5001

Uses only the Python standard library (no pip install needed).
Put app.py, index.html and style.css in the same folder.
"""

import html
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

BASE_DIR = Path(__file__).resolve().parent
HOST, PORT = "127.0.0.1", 5001

COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "123456789", "qwerty",
    "abc123", "111111", "iloveyou", "admin", "welcome", "letmein",
    "monkey", "dragon", "football", "login", "passw0rd", "qwerty123",
}


def analyze(password: str) -> str:
    """Return the HTML that replaces {{RESULT}} in index.html."""
    length = len(password)

    checks = [
        ("At least 8 characters", length >= 8),
        ("At least 12 characters", length >= 12),
        ("Contains lowercase letters", bool(re.search(r"[a-z]", password))),
        ("Contains uppercase letters", bool(re.search(r"[A-Z]", password))),
        ("Contains numbers", bool(re.search(r"\d", password))),
        ("Contains symbols", bool(re.search(r"[^A-Za-z0-9]", password))),
        ("Not a commonly used password", password.lower() not in COMMON_PASSWORDS),
        ("No 3+ repeated characters in a row", not re.search(r"(.)\1\1", password)),
    ]

    score = sum(12 for _, ok in checks if ok)
    score += min(max(length - 12, 0), 4)  # small bonus for extra length
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 15)
    score = max(0, min(score, 100))

    if score < 25:
        cls, label = "very-weak", "Very Weak"
    elif score < 45:
        cls, label = "weak", "Weak"
    elif score < 65:
        cls, label = "medium", "Medium"
    elif score < 85:
        cls, label = "strong", "Strong"
    else:
        cls, label = "very-strong", "Very Strong"

    check_items = "".join(
        f'<li class="{"ok" if ok else "bad"}">{"✔" if ok else "✘"} {html.escape(text)}</li>'
        for text, ok in checks
    )

    tips = []
    if length < 12:
        tips.append("Use 12 or more characters.")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
        tips.append("Mix uppercase and lowercase letters.")
    if not re.search(r"\d", password):
        tips.append("Add some numbers.")
    if not re.search(r"[^A-Za-z0-9]", password):
        tips.append("Add symbols such as ! @ # $ %.")
    if password.lower() in COMMON_PASSWORDS:
        tips.append("This is a very common password. Choose something unique.")
    if re.search(r"(.)\1\1", password):
        tips.append("Avoid repeating the same character many times.")
    if not tips:
        tips.append("Great password! Use a password manager and never reuse it.")

    tip_items = "".join(f"<li>💡 {html.escape(t)}</li>" for t in tips)

    return (
        f'<div class="meter"><div class="bar {cls}" style="width:{score}%"></div></div>'
        f'<div class="strength-label {cls}">{label}</div>'
        f'<div class="meta">Length: {length} characters · Score: {score}/100</div>'
        f'<ul class="checks">{check_items}</ul>'
        f"<h3>Tips</h3>"
        f'<ul class="tips">{tip_items}</ul>'
    )


def render_page(result_html: str = "") -> bytes:
    page = (BASE_DIR / "index.html").read_text(encoding="utf-8")
    return page.replace("{{RESULT}}", result_html).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, render_page(), "text/html; charset=utf-8")
        elif path == "/style.css":
            css = (BASE_DIR / "style.css").read_bytes()
            self._send(200, css, "text/css; charset=utf-8")
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 10_000:  # reject oversized bodies
            self._send(413, b"Request too large", "text/plain; charset=utf-8")
            return
        data = parse_qs(self.rfile.read(length).decode("utf-8"))
        password = data.get("password", [""])[0]
        self._send(200, render_page(analyze(password)), "text/html; charset=utf-8")

    def log_message(self, format, *args):
        # Only log the request line + status; never the form body or password.
        print(f"{self.address_string()} - {format % args}")


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print(f"SecureX running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
