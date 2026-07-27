import base64
import csv
import hashlib
import json
import os
import secrets
import sqlite3

import jwt
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "data", "egtcg.db")
CARDS_CSV = os.path.join(BASE, "data", "cards.csv")
SECRET_DIR = os.path.join(BASE, "secret")
FLAGS_PATH = os.path.join(SECRET_DIR, "flags.json")
BACKUP_DIR = os.path.join(BASE, "backup")
STATIC_DIR = os.path.join(BASE, "static")
PRIV_PATH = os.path.join(SECRET_DIR, "eg_priv.pem")
PUB_PATH = os.path.join(STATIC_DIR, "eg_pub.pem")
CONFIG_PATH = os.path.join(SECRET_DIR, "config.json")


def hash_pw(p):
    return hashlib.sha256(p.encode()).hexdigest()


# Obfuscated defaults so the repo is not greppable for answers. Decoded at build
# time into gitignored files under secret/.
_DEFAULT_CONFIG_B64 = {
    "recon_pw":    "UjNjMG5PcHMyMDI2S3g=",
    "creds_pw":    "Q3IzZHNWYXVsdDIwMjZacQ==",
    "report_key":  "cmVwb3J0X2tleV9lZ190Y2c=",
    "ai_token":    "RUdBSV9PVkVSUklERV8zRjlB",
    "ai_aes_key":  "OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTU=",
    "ai_aes_iv":   "MWYyZDNjNGI1YTY5Nzg4MDAwMTEyMjMzNDQ1NTY2YWE=",
    "ai_xor_key":  "RUdBSQ==",
    "mod_cookie":  "ZWdtb2Rfc2Vzc2lvbg==",
}
_DEFAULT_FLAGS_B64 = {
    "rce":       "RUd7cDFja2wzX3VwbDA0ZF9yYzN9",
    "jwt":       "RUd7and0XzRsZ19jMG5mdXMxMG59",
    "sqli":      "RUd7dW4xMG5fYjRzM2Rfc3FsaX0=",
    "lfi":       "RUd7cDR0aF90cjR2M3JzNGxfbGYxfQ==",
    "idor":      "RUd7MWQwcl9oMWRkM25fNHAxfQ==",
    "recon":     "RUd7cjNjMG5fZDFzYzB2M3J5fQ==",
    "creds":     "RUd7cGw0MW50M3h0X2NyM2RzX2R1bXB9",
    "ssrf":      "RUd7c3NyZl8yXzFudDNybjRsXzRwMX0=",
    "xss":       "RUd7c3QwcjNkX3hzc19jMDBrMTNfdGgzZnR9",
    "ai_leak":   "RUd7bGxtX2NoNDFuX3Q0azMwdjNyfQ==",
}


def load_flags():
    os.makedirs(SECRET_DIR, exist_ok=True)
    if not os.path.exists(FLAGS_PATH):
        flags = {k: base64.b64decode(v).decode() for k, v in _DEFAULT_FLAGS_B64.items()}
        with open(FLAGS_PATH, "w", encoding="utf-8") as f:
            json.dump(flags, f, indent=2)
    with open(FLAGS_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_config():
    os.makedirs(SECRET_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        conf = {k: base64.b64decode(v).decode() for k, v in _DEFAULT_CONFIG_B64.items()}
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(conf, f, indent=2)
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def ensure_keys():
    """Generate the RS256 private key if missing. The public key is NOT written
    to a served file: the app derives it and publishes it only via JWKS, so the
    JWT challenge has to recover it the realistic way."""
    os.makedirs(SECRET_DIR, exist_ok=True)
    # remove any stale public pem that used to sit under static/ (web-served)
    if os.path.exists(PUB_PATH):
        os.remove(PUB_PATH)
    if os.path.exists(PRIV_PATH):
        return
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIV_PATH, "wb") as f:
        f.write(key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                  _ser.NoEncryption()))
    print("Generated RSA private key. Public key is served via JWKS")


def write_backup_token(recon_pw):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    payload = {
        "iss": "eg-backup-service",
        "note": "temp creds for automated recon admin, rotate before prod",
        "username": "EGAdminRecon",
        "password": recon_pw,
        "role": "admin",
    }
    tok = jwt.encode(payload, "eg-legacy-backup-key", algorithm="HS256")
    with open(os.path.join(BACKUP_DIR, "eg_token.bak"), "w", encoding="utf-8") as f:
        f.write(tok + "\n")


def rnd():
    return secrets.token_urlsafe(24)


def build():
    flags = load_flags()
    conf = load_config()
    ensure_keys()
    write_backup_token(conf["recon_pw"])
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(SECRET_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ---------------- users ----------------
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            display_name TEXT NOT NULL,
            secret TEXT
        )
        """
    )
    # the secret column only holds the SQLi flag on one row
    users = [
        # id, username, password, role, display_name, secret
        (1,  "EGAdmin",              rnd(),                    "admin", "EGAdmin",            None),
        (2,  "player",               "player123",              "user",  "Player One",         None),
        (3,  "collector",            "collector123",           "user",  "Collector",          None),
        (4,  "EGAdminSQLi",          rnd(),                    "admin", "SQLi Admin",         flags["sqli"]),
        (5,  "EGAdminIDOR",          rnd(),                    "admin", "IDOR Admin",         None),
        (6,  "EGAdminRecon",         conf["recon_pw"],         "admin", "Recon Admin",        None),
        (7,  "EGAdminCreds",         conf["creds_pw"],         "admin", "Creds Admin",        None),
        (8,  "EGAdminJWT",           rnd(),                    "admin", "JWT Admin",          None),
        (9,  "EGAdminRCE",           rnd(),                    "admin", "RCE Admin",          None),
        (10, "EGAdminLFI",           rnd(),                    "admin", "LFI Admin",          None),
        (11, "EGAdminSSRF",          rnd(),                    "admin", "SSRF Admin",         None),
        (12, "EGAI",                 rnd(),                    "admin", "Assistant Admin",    None),
        (13, "EGSoc",                "soc-console-2026",       "soc",   "SOC Analyst",        None),
    ]
    # store hashed passwords so a dump never leaks a usable login
    users = [(i, u, hash_pw(p), r, d, s) for (i, u, p, r, d, s) in users]
    cur.executemany(
        "INSERT INTO users (id, username, password, role, display_name, secret) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        users,
    )

    # ---------------- cards ----------------
    cur.execute(
        """
        CREATE TABLE cards (
            card_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            rarity TEXT NOT NULL,
            power INTEGER NOT NULL,
            description TEXT
        )
        """
    )
    with open(CARDS_CSV, newline="", encoding="utf-8") as f:
        rows = [
            (r["card_id"], r["name"], r["rarity"], int(r["power"]), r["description"])
            for r in csv.DictReader(f)
        ]
    cur.executemany(
        "INSERT INTO cards (card_id, name, rarity, power, description) VALUES (?, ?, ?, ?, ?)",
        rows,
    )

    # ---------------- collections ----------------
    cur.execute(
        "CREATE TABLE collections (user_id INTEGER NOT NULL, card_id TEXT NOT NULL)"
    )
    collections = [
        (2, "EG04"), (2, "EG02"), (2, "EG08"),
        (3, "EG01"), (3, "EG07"), (3, "EG03"),
        (1, "EG05"), (1, "EG06"), (1, "EG01"),
    ]
    cur.executemany(
        "INSERT INTO collections (user_id, card_id) VALUES (?, ?)", collections
    )

    # ---------------- SOC tables ----------------
    cur.execute(
        """
        CREATE TABLE soc_events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            ip TEXT,
            username TEXT,
            action TEXT NOT NULL,
            severity TEXT NOT NULL,
            detail TEXT,
            status TEXT NOT NULL DEFAULT 'open'
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE tickets (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            mitre TEXT,
            event_id INTEGER,
            status TEXT NOT NULL DEFAULT 'open'
        )
        """
    )
    cur.execute("CREATE TABLE blocklist (ip TEXT PRIMARY KEY, ts TEXT NOT NULL)")

    # card reports and the collect sink
    cur.execute(
        """
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            author TEXT,
            content TEXT NOT NULL,
            reviewed INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE collected (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            ip TEXT,
            value TEXT
        )
        """
    )

    conn.commit()
    conn.close()

    # ---------------- on-disk files ----------------
    with open(os.path.join(SECRET_DIR, "eg_lfi.txt"), "w", encoding="utf-8") as f:
        f.write(flags["lfi"] + "\n")
    with open(os.path.join(SECRET_DIR, "eg_rce.flag"), "w", encoding="utf-8") as f:
        f.write(flags["rce"] + "\n")
    # drop stale readable copies from older builds
    for stale in (os.path.join(SECRET_DIR, "eg_rce.txt"),
                  os.path.join(BASE, "rceflag.txt")):
        if os.path.exists(stale):
            os.remove(stale)

    print(f"Database built at {DB_PATH}")
    print("Accounts ready. SOC console: EGSoc / soc-console-2026")


if __name__ == "__main__":
    build()
