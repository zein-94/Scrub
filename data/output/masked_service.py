"""
user_service.py
User authentication and data access service.
"""

import os
import pickle
import random
import hashlib
import subprocess
import yaml
from datetime import datetime

import requests
import jwt


# ── Hardcoded credentials (should be in env vars) ────────────────────────────

AWS_ACCESS_KEY     = "{{AWS_ACCESS_KEY_1}}"
AWS_SECRET_KEY     = "{{SECRET_1}}"
STRIPE_SECRET_KEY  = "{{STRIPE_KEY_1}}"
OPENAI_API_KEY     = "{{API_KEY_1}}"
ANTHROPIC_API_KEY  = "{{API_KEY_2}}"
SENDGRID_KEY       = "{{SENDGRID_KEY_1}}"
GITHUB_TOKEN       = "{{GITHUB_TOKEN_1}}"

DB_PASSWORD        = "{{PASSWORD_1}}"
JWT_SECRET         = "{{SECRET_2}}"
SESSION_SECRET     = "{{SECRET_3}}"

DB_CONNECTION      = "{{CONNECTION_STRING_1}}"
REDIS_URL          = "{{CONNECTION_STRING_2}}"

PRIVATE_KEY = """{{RSA_PRIVATE_KEY_1}}"""

SLACK_WEBHOOK = "{{WEBHOOK_URL_1}}"


# ── Hardcoded server info ─────────────────────────────────────────────────────

API_BASE_URL    = "http://internal-api.acmecorp.com/v2"     # plain HTTP
INTERNAL_HOST   = "{{IP_ADDRESS_1}}"
ADMIN_SERVER    = "{{IP_ADDRESS_2}}"
SERVER_BINDING  = "{{IP_ADDRESS_3}}"


# ── Security vulnerabilities ──────────────────────────────────────────────────

def get_user(user_id):
    """Fetch user from database — SQL injection risk."""
    import psycopg2
    conn = psycopg2.connect(DB_CONNECTION)
    cursor = conn.cursor()
    # VULNERABILITY: f-string in SQL query
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def search_users(search_term):
    """Search users — SQL injection via string concatenation."""
    import psycopg2
    conn = psycopg2.connect(DB_CONNECTION)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()


def run_report(report_name):
    """Generate report — command injection risk."""
    # VULNERABILITY: user input passed to shell
    os.system(f"python reports/{report_name}.py")


def run_script(script_path):
    """Run a script — another command injection vector."""
    # VULNERABILITY: shell=True with user input
    subprocess.run(f"bash {script_path}", shell=True)


def hash_password(password):
    """Hash a password — weak algorithm."""
    # VULNERABILITY: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    """Generate a session token — insecure RNG."""
    # VULNERABILITY: random is not cryptographically secure
    return str(random.randint(100000, 999999))


def load_user_session(session_file):
    """Load user session — unsafe deserialization."""
    with open(session_file, "rb") as f:
        # VULNERABILITY: pickle.loads on untrusted data
        return pickle.loads(f.read())


def load_config(config_path):
    """Load config file — unsafe YAML."""
    with open(config_path, "r") as f:
        # VULNERABILITY: yaml.load without SafeLoader
        return yaml.load(f.read())


def execute_filter(filter_expr):
    """Dynamic filter — arbitrary code execution."""
    # VULNERABILITY: eval on user input
    return eval(filter_expr)


def call_external_api(endpoint, data):
    """Call an external service — TLS verification disabled."""
    # VULNERABILITY: verify=False disables certificate checking
    return requests.post(
        f"{API_BASE_URL}/{endpoint}",
        json=data,
        verify=False,
    )


def create_jwt(user_id):
    """Create a JWT — hardcoded secret."""
    payload = {"user_id": user_id, "exp": datetime.utcnow()}
    # VULNERABILITY: hardcoded JWT secret
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def open_user_file(filename):
    """Open a user-provided file — path traversal risk."""
    # VULNERABILITY: unsanitized filename from user input
    return open(f"/var/app/uploads/{filename}", "r").read()


def log_login(username, password):
    """Log a login attempt — sensitive data in logs."""
    # VULNERABILITY: logging password in plaintext
    print(f"Login attempt: username={username}, password={password}")


def start_server():
    """Start the Flask app — debug mode on."""
    from flask import Flask
    app = Flask(__name__)
    # VULNERABILITY: debug=True in production
    app.run(host=SERVER_BINDING, port=5000, debug=True)