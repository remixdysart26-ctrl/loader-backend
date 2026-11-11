import secrets, hashlib, sqlite3, os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import jwt

app = FastAPI()
DB = "licenses.db"
JWT_SECRET = os.environ.get("JWT_SECRET")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "default_admin_pass_123")

if not JWT_SECRET:
    raise RuntimeError("Set JWT_SECRET env var")

ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

def new_key():
    raw = "".join(secrets.choice(ALPHABET) for _ in range(16))
    return "APP-" + "-".join(raw[i:i+4] for i in range(0, 16, 4))

def hash_key(k):
    return hashlib.sha256(k.encode()).hexdigest()

def init_db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS licenses(
        key_hash TEXT PRIMARY KEY, email TEXT, created_at TEXT,
        expires_at TEXT, revoked INTEGER DEFAULT 0, last_device TEXT)""")
    con.commit(); con.close()
init_db()

class AuthReq(BaseModel):
    key: str
    device_id: str

class RefreshReq(BaseModel):
    refresh_token: str

class GenReq(BaseModel):
    email: str
    days: int = None

@app.post("/admin/gen")
def generate_key(req: GenReq, x_admin_password: str = Header(None)):
    if x_admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Unauthorized")
    
    key = new_key()
    now = datetime.now(timezone.utc)
    exp = None # Expiry is calculated on first login
    
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO licenses VALUES (?,?,?,?,?,?)",
              (hash_key(key), req.email, now.isoformat(), exp, 0, None))
    c.commit(); c.close()
    
    return {"key": key, "expires_at": exp, "email": req.email}

@app.post("/auth")
def auth(req: AuthReq):
    c = sqlite3.connect(DB)
    row = c.execute("SELECT email, expires_at, revoked, last_device FROM licenses WHERE key_hash=?",
                    (hash_key(req.key.strip().upper()),)).fetchone()
    if not row:
        c.close(); raise HTTPException(401, "invalid key")
    email, exp, revoked, last_device = row
    if revoked:
        c.close(); raise HTTPException(403, "revoked")
    if exp and datetime.fromisoformat(exp) < datetime.now(timezone.utc):
        c.close(); raise HTTPException(403, "expired")
    if last_device is None:
        c.execute("UPDATE licenses SET last_device=? WHERE key_hash=?",
                  (req.device_id, hash_key(req.key.strip().upper())))
    elif last_device != req.device_id:
        c.close(); raise HTTPException(403, "key bound to another device")
    c.commit(); c.close()

    access = jwt.encode({"email": email, "typ": "access",
                         "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
                        JWT_SECRET, algorithm="HS256")
    refresh = jwt.encode({"email": email, "typ": "refresh",
                          "exp": datetime.now(timezone.utc) + timedelta(days=30)},
                         JWT_SECRET, algorithm="HS256")
    return {"token": access, "refresh_token": refresh, "expires_at": exp}

@app.post("/refresh")
def refresh(req: RefreshReq):
    try:
        payload = jwt.decode(req.refresh_token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "bad refresh token")
    if payload.get("typ") != "refresh":
        raise HTTPException(401, "not a refresh token")
    token = jwt.encode({"email": payload["email"], "typ": "access",
                        "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
                       JWT_SECRET, algorithm="HS256")
    return {"token": token}
