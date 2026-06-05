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



AWS_ACCESS_KEY     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY  = "sk_live_51OaBcDEfGhIjKlMnOpQrStUv"
OPENAI_API_KEY     = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
ANTHROPIC_API_KEY  = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
SENDGRID_KEY       = "SG.abcdefghijklmnop.qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12"
GITHUB_TOKEN       = "ghp_abcdefghijklmnopqrstuvwxyz123456"

DB_PASSWORD        = "SuperSecret@DB2024!"
JWT_SECRET         = "my_jwt_secret_key"
SESSION_SECRET     = "sess123"

DB_CONNECTION      = "postgresql://admin:SuperSecret@DB2024!@192.168.1.45:5432/prod_db"
REDIS_URL          = "redis://:redispass123@10.0.0.12:6379/0"

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7YB0S1H
ROBBiMNPDeqBMFJXKDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----"""

SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"



API_BASE_URL    = "http://internal-api.acmecorp.com/v2"     # plain HTTP
INTERNAL_HOST   = "10.0.0.55"
ADMIN_SERVER    = "192.168.1.100"
SERVER_BINDING  = "0.0.0.0"



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
    os.system(f"python reports/{report_name}.py")


def run_script(script_path):
    """Run a script — another command injection vector."""
    subprocess.run(f"bash {script_path}", shell=True)


def hash_password(password):
    """Hash a password — weak algorithm."""
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    """Generate a session token — insecure RNG."""
    return str(random.randint(100000, 999999))


def load_user_session(session_file):
    """Load user session — unsafe deserialization."""
    with open(session_file, "rb") as f:
        return pickle.loads(f.read())


def load_config(config_path):
    """Load config file — unsafe YAML."""
    with open(config_path, "r") as f:
        return yaml.load(f.read())


def execute_filter(filter_expr):
    """Dynamic filter — arbitrary code execution."""
    return eval(filter_expr)


def call_external_api(endpoint, data):
    """Call an external service — TLS verification disabled."""
    return requests.post(
        f"{API_BASE_URL}/{endpoint}",
        json=data,
        verify=False,
    )


def create_jwt(user_id):
    """Create a JWT — hardcoded secret."""
    payload = {"user_id": user_id, "exp": datetime.utcnow()}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def open_user_file(filename):
    """Open a user-provided file — path traversal risk."""
    return open(f"/var/app/uploads/{filename}", "r").read()


def log_login(username, password):
    """Log a login attempt — sensitive data in logs."""
    print(f"Login attempt: username={username}, password={password}")


def start_server():
    """Start the Flask app — debug mode on."""
    from flask import Flask
    app = Flask(__name__)
    app.run(host=SERVER_BINDING, port=5000, debug=True)