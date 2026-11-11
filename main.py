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
    # Added "days" column to remember how long the sub is supposed to last
    con.execute("""CREATE TABLE IF NOT EXISTS licenses(
        key_hash TEXT PRIMARY KEY, 
        email TEXT, 
        created_at TEXT,
        expires_at TEXT, 
        revoked INTEGER DEFAULT 0, 
        last_device TEXT,
        days INTEGER
    )""")
    con.commit(); con.close()

# Delete the old database if the columns changed so it updates cleanly
if os.path.exists(DB):
    try:
        con = sqlite3.connect(DB)
        con.execute("SELECT days FROM licenses LIMIT 1")
        con.close()
    except sqlite3.OperationalError:
        os.remove(DB) # Deletes old DB to prevent errors

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
    
    # When generating, expires_at is None. It starts counting on first login!
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO licenses (key_hash, email, created_at, expires_at, revoked, last_device, days) VALUES (?,?,?,?,?,?,?)",
              (hash_key(key), req.email, now.isoformat(), None, 0, None, req.days))
    c.commit(); c.close()
    
    return {"key": key, "days": req.days, "email": req.email}

@app.post("/auth")
def auth(req: AuthReq):
    c = sqlite3.connect(DB)
    row = c.execute("SELECT email, expires_at, revoked, last_device, days FROM licenses WHERE key_hash=?",
                    (hash_key(req.key.strip().upper()),)).fetchone()
    if not row:
        c.close(); raise HTTPException(401, "invalid key")
        
    email, exp, revoked, last_device, days = row
    
    if revoked:
        c.close(); raise HTTPException(403, "revoked")
        
    # If they have already logged in before, check the date
    if exp and datetime.fromisoformat(exp) < datetime.now(timezone.utc):
        c.close(); raise HTTPException(403, "expired")
        
    # If this is their very first time logging in
    if last_device is None:
        new_exp = None
        # If the key has a time limit, start the clock NOW
        if days is not None:
            new_exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            
        c.execute("UPDATE licenses SET last_device=?, expires_at=? WHERE key_hash=?",
                  (req.device_id, new_exp, hash_key(req.key.strip().upper())))
        exp = new_exp
    elif last_device != req.device_id:
        c.close(); raise HTTPException(403, "key bound to another device")
        
    c.commit(); c.close()

    access = jwt.encode({"email": email, "typ": "access",
                         "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
                        JWT_SECRET, algorithm="HS256")
    refresh = jwt.encode({"email": email, "typ": "refresh",
                          "exp": datetime.now(timezone.utc) + timedelta(days=30)},
                         JWT_SECRET, algorithm="HS256")
                         
    # Fallback to "Lifetime" if no expiry
    return {"token": access, "refresh_token": refresh, "expires_at": exp if exp else "Lifetime"}

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
