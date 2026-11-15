from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import sqlite3

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT.parent / "vendorguard.db"
STATIC_DIR = ROOT / "static"

app = FastAPI(title="VendorGuard", version="1.1.0")


def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def hash_pw(pw):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 180000).hex()
    return salt.hex() + "$" + digest


def verify_pw(pw, stored):
    try:
        salt_hex, expected = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac(
            "sha256", pw.encode(), bytes.fromhex(salt_hex), 180000
        ).hex()
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, full_name TEXT,
            password_hash TEXT, role TEXT, status TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS documents(
            id TEXT PRIMARY KEY, name TEXT, category TEXT, description TEXT,
            content TEXT, active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS permissions(
            user_id INTEGER, document_id TEXT,
            PRIMARY KEY(user_id, document_id)
        );
        CREATE TABLE IF NOT EXISTS access_logs(
            id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT,
            document_id TEXT, action TEXT, result TEXT, detail TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS honeytokens(
            id TEXT PRIMARY KEY, label TEXT, active INTEGER DEFAULT 1,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT,
            kind TEXT, severity TEXT, description TEXT,
            status TEXT DEFAULT 'open', created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, user_id INTEGER, expires_at TEXT
        );
        """)

        if not c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            c.execute(
                "INSERT INTO users VALUES(NULL,?,?,?,?,?,?)",
                ("admin", "Security Administrator", hash_pw("Admin@12345"),
                 "admin", "active", now())
            )

        if not c.execute("SELECT 1 FROM users WHERE username='vendor1'").fetchone():
            c.execute(
                "INSERT INTO users VALUES(NULL,?,?,?,?,?,?)",
                ("vendor1", "Aster Engineering Contractor", hash_pw("Vendor@12345"),
                 "contractor", "active", now())
            )

        docs = [
            ("DOC-101", "Engineering Overview.pdf", "Engineering",
             "General engineering reference",
             "SYNTHETIC DEMO DOCUMENT. No real facility information."),
            ("DOC-102", "Maintenance Schedule.pdf", "Maintenance",
             "Fictional maintenance reference",
             "SYNTHETIC DEMO DOCUMENT. Fictional maintenance schedule."),
            ("DOC-103", "Inspection Summary.pdf", "Inspection",
             "Fictional inspection summary",
             "SYNTHETIC DEMO DOCUMENT. Training content."),
            ("DOC-104", "Project Requirements.pdf", "Project",
             "Fictional project reference",
             "SYNTHETIC DEMO DOCUMENT. Fictional project requirements.")
        ]
        for d in docs:
            c.execute(
                "INSERT OR IGNORE INTO documents(id,name,category,description,content) "
                "VALUES(?,?,?,?,?)", d
            )

        vendor = c.execute(
            "SELECT id FROM users WHERE username='vendor1'"
        ).fetchone()
        for did in ("DOC-101", "DOC-102", "DOC-103"):
            c.execute(
                "INSERT OR IGNORE INTO permissions VALUES(?,?)",
                (vendor["id"], did)
            )

        # Keep one persistent decoy identifier. It is never returned by /api/documents.
        if not c.execute("SELECT 1 FROM honeytokens WHERE active=1").fetchone():
            c.execute(
                "INSERT INTO honeytokens VALUES(?,?,1,?)",
                ("HT-" + secrets.token_hex(5).upper(),
                 "Archived vendor handover index decoy", now())
            )


init_db()


class Login(BaseModel):
    username: str = Field(min_length=2, max_length=60)
    password: str = Field(min_length=6, max_length=128)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    full_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    document_ids: list[str] = Field(default_factory=list)


def log(uid, uname, did, action, result, detail):
    with db() as c:
        c.execute(
            "INSERT INTO access_logs(user_id,username,document_id,action,result,detail,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (uid, uname, did, action, result, detail, now())
        )


def incident(uid, uname, kind, severity, desc):
    with db() as c:
        c.execute(
            "INSERT INTO incidents(user_id,username,kind,severity,description,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (uid, uname, kind, severity, desc, now())
        )


def suspend(uid):
    with db() as c:
        c.execute(
            "UPDATE users SET status='suspended' WHERE id=? AND role='contractor'",
            (uid,)
        )
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))


def current(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in")
    with db() as c:
        row = c.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires_at>?",
            (authorization[7:], now())
        ).fetchone()
    if not row:
        raise HTTPException(401, "Session expired")
    if row["status"] != "active":
        raise HTTPException(403, "Account suspended. Ask an administrator to restore access.")
    return dict(row)


def admin(u=Depends(current)):
    if u["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return u


def contractor(u=Depends(current)):
    if u["role"] != "contractor":
        raise HTTPException(403, "Contractor access required")
    return u


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"application": "VendorGuard", "status": "online", "database": "connected"}


@app.post("/api/auth/login")
def login(b: Login):
    with db() as c:
        u = c.execute(
            "SELECT * FROM users WHERE username=?", (b.username,)
        ).fetchone()

    if not u or not verify_pw(b.password, u["password_hash"]):
        log(u["id"] if u else None, b.username, None,
            "LOGIN", "DENIED", "Invalid credentials")
        raise HTTPException(401, "Invalid username or password")

    if u["status"] != "active":
        log(u["id"], u["username"], None, "LOGIN", "DENIED",
            "Login blocked: contractor account is suspended")
        raise HTTPException(403, "Vendor account is suspended. Log in as admin and restore the contractor.")

    token = secrets.token_urlsafe(32)
    expiry = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
    with db() as c:
        c.execute("INSERT INTO sessions VALUES(?,?,?)", (token, u["id"], expiry))
    log(u["id"], u["username"], None, "LOGIN", "ALLOWED", "Successful login")
    return {
        "access_token": token, "token_type": "bearer",
        "role": u["role"], "full_name": u["full_name"],
        "username": u["username"]
    }


@app.post("/api/auth/logout")
def logout(u=Depends(current), authorization: str | None = Header(default=None)):
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (authorization[7:],))
    return {"message": "Logged out"}


@app.get("/api/me")
def me(u=Depends(current)):
    return {k: u[k] for k in ("id", "username", "full_name", "role", "status")}


@app.get("/api/documents")
def documents(u=Depends(current)):
    with db() as c:
        if u["role"] == "admin":
            rows = c.execute(
                "SELECT id,name,category,description FROM documents WHERE active=1"
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT d.id,d.name,d.category,d.description FROM documents d "
                "JOIN permissions p ON p.document_id=d.id "
                "WHERE p.user_id=? AND d.active=1", (u["id"],)
            ).fetchall()
    return [dict(x) for x in rows]


@app.get("/api/vendor/decoy-link")
def vendor_decoy_link(u=Depends(contractor)):
    """Return the planted lure link to an authenticated vendor, not in the document catalogue."""
    with db() as c:
        h = c.execute(
            "SELECT id FROM honeytokens WHERE active=1 ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    if not h:
        raise HTTPException(404, "No active archive reference is available")
    return {
        "label": "Archived vendor handover index",
        "description": "Reference index retained for the previous project handover.",
        "document_id": h["id"]
    }


@app.post("/api/documents/{did}/download")
def download(did: str, u=Depends(current)):
    with db() as c:
        d = c.execute(
            "SELECT * FROM documents WHERE id=? AND active=1", (did,)
        ).fetchone()
        h = None if d else c.execute(
            "SELECT * FROM honeytokens WHERE id=? AND active=1", (did,)
        ).fetchone()

    # The alert is generated only when an authenticated user actually requests the decoy.
    if h:
        log(u["id"], u["username"], did, "HONEYTOKEN_ACCESS", "TRIGGERED",
            "Authenticated user requested the planted archived handover decoy")
        incident(
            u["id"], u["username"], "HONEYTOKEN_ACCESS", "critical",
            f"Vendor {u['username']} attempted to access the planted archived handover decoy."
        )
        suspend(u["id"])
        raise HTTPException(
            403, "Decoy resource accessed. A critical security incident was recorded and this vendor account has been suspended."
        )

    if not d:
        log(u["id"], u["username"], did, "DOWNLOAD", "NOT_FOUND", "Unknown document")
        raise HTTPException(404, "Document not found")

    with db() as c:
        allowed = (
            u["role"] == "admin" or
            c.execute(
                "SELECT 1 FROM permissions WHERE user_id=? AND document_id=?",
                (u["id"], did)
            ).fetchone()
        )

    if not allowed:
        log(u["id"], u["username"], did, "DOWNLOAD", "DENIED",
            "No document permission")
        incident(
            u["id"], u["username"], "UNAUTHORIZED_ACCESS", "high",
            f"Attempted access to {d['name']} without permission"
        )
        raise HTTPException(403, "You do not have permission")

    log(u["id"], u["username"], did, "DOWNLOAD", "ALLOWED",
        f"Downloaded {d['name']}")

    with db() as c:
        count = c.execute(
            "SELECT COUNT(*) n FROM access_logs WHERE user_id=? "
            "AND action='DOWNLOAD' AND result='ALLOWED' AND created_at>=?",
            (u["id"], (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat())
        ).fetchone()["n"]

    if count >= 8 and u["role"] == "contractor":
        incident(
            u["id"], u["username"], "EXCESSIVE_DOWNLOADS", "high",
            f"{count} successful downloads within five minutes"
        )
        suspend(u["id"])

    return {
        "document_id": d["id"], "filename": d["name"],
        "content": d["content"], "message": "Synthetic document download recorded"
    }


@app.get("/api/admin/overview")
def overview(a=Depends(admin)):
    with db() as c:
        q = lambda sql: c.execute(sql).fetchone()["n"]
        return {
            "contractors": q("SELECT COUNT(*) n FROM users WHERE role='contractor'"),
            "active_contractors": q("SELECT COUNT(*) n FROM users WHERE role='contractor' AND status='active'"),
            "access_events": q("SELECT COUNT(*) n FROM access_logs"),
            "open_incidents": q("SELECT COUNT(*) n FROM incidents WHERE status='open'"),
            "honeytoken_alerts": q("SELECT COUNT(*) n FROM incidents WHERE kind='HONEYTOKEN_ACCESS'")
        }


@app.get("/api/admin/users")
def users(a=Depends(admin)):
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,username,full_name,role,status,created_at FROM users "
            "WHERE role='contractor' ORDER BY id DESC"
        ).fetchall()]


@app.post("/api/admin/users")
def create_user(b: UserCreate, a=Depends(admin)):
    with db() as c:
        try:
            cur = c.execute(
                "INSERT INTO users VALUES(NULL,?,?,?,?,?,?)",
                (b.username, b.full_name, hash_pw(b.password),
                 "contractor", "active", now())
            )
            uid = cur.lastrowid
            for did in b.document_ids:
                if not c.execute(
                    "SELECT 1 FROM documents WHERE id=?", (did,)
                ).fetchone():
                    raise HTTPException(400, f"Unknown document {did}")
                c.execute(
                    "INSERT OR IGNORE INTO permissions VALUES(?,?)", (uid, did)
                )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username already exists")
    return {"message": "Contractor created", "user_id": uid}


@app.post("/api/admin/users/{uid}/suspend")
def admin_suspend(uid: int, a=Depends(admin)):
    suspend(uid)
    return {"message": "Suspended"}


@app.post("/api/admin/users/{uid}/restore")
def admin_restore(uid: int, a=Depends(admin)):
    with db() as c:
        c.execute(
            "UPDATE users SET status='active' WHERE id=? AND role='contractor'",
            (uid,)
        )
    return {"message": "Restored"}


@app.get("/api/admin/logs")
def logs(a=Depends(admin)):
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM access_logs ORDER BY id DESC LIMIT 100"
        ).fetchall()]


@app.get("/api/admin/incidents")
def incidents(a=Depends(admin)):
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT 100"
        ).fetchall()]


@app.post("/api/admin/incidents/{iid}/resolve")
def resolve(iid: int, a=Depends(admin)):
    with db() as c:
        c.execute("UPDATE incidents SET status='resolved' WHERE id=?", (iid,))
    return {"message": "Resolved"}


@app.get("/api/admin/honeytokens")
def honeytokens(a=Depends(admin)):
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,label,active,created_at FROM honeytokens"
        ).fetchall()]


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
