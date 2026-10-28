from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import hashlib
import os
import hmac
import sqlite3
import re
from typing import Optional, List

# Initialize FastAPI
app = FastAPI(
    title="Email Spoof Detection API",
    description="Backend microservice for domain-restricted auth and spoof detection.",
    version="2.0.0"
)

# CORS Middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE = "users.db"

# =====================================================================
# DATABASE INITIALIZATION
# =====================================================================

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'Analyst'
        )
    """)
    
    # Analysis Logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            from_header TEXT,
            reply_to TEXT,
            risk_score INTEGER,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()

init_db()

# =====================================================================
# REQUEST & RESPONSE MODELS
# =====================================================================

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class EmailAnalysisRequest(BaseModel):
    from_header: str
    reply_to: Optional[str] = ""
    return_path: Optional[str] = ""
    spf_result: Optional[str] = "none"
    dkim_result: Optional[str] = "none"
    dmarc_result: Optional[str] = "none"
    body_text: Optional[str] = ""

# =====================================================================
# AUTHENTICATION HELPERS & ENDPOINTS
# =====================================================================

# =====================================================================
# ALLOWED DOMAINS LIST
# =====================================================================

ALLOWED_DOMAINS = ["gmail.com", "yahoo.com", "icloud.com","students.cavendish.co.zm"]

def is_valid_domain_email(email: str) -> bool:
    """Validates that the email domain is in the allowed list (gmail, yahoo, icloud, students.cavendish.co.zm)."""
    email_clean = email.strip().lower()
    if "@" not in email_clean:
        return False
    domain = email_clean.split("@")[-1]
    return domain in ALLOWED_DOMAINS

def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()
    return f"{salt.hex()}:{hashed}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verifies a provided password against the stored salt:hash string."""
    try:
        salt_hex, stored_hash = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        computed_hash = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt, 100000).hex()
        return hmac.compare_digest(computed_hash, stored_hash)
    except Exception:
        return False

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    name = data.name.strip()
    email = data.email.strip().lower()
    password = data.password

    if not name or not email or not password:
        raise HTTPException(status_code=400, detail="All fields are required.")

    # Rule 1: Enforce @shamshani.com domain restriction
    if not is_valid_domain_email(email):
        raise HTTPException(
            status_code=400,
            detail=f"Registration restricted! You must use an email address from one of these domains: {', '.join(ALLOWED_DOMAINS)}."
        )

    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long.")

    stored_pwd = hash_password(password)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, stored_pwd)
        )
        conn.commit()
        return {"message": f"Account created successfully for {email}."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="An account with this email address already exists.")
    finally:
        conn.close()

@app.post("/login")
def login(data: LoginRequest):
    email = data.email.strip().lower()
    password = data.password
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Please provide both email and password")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Normalize email lookup to lowercase
    cursor.execute("SELECT name, email, password, role FROM users WHERE LOWER(email) = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail=f"User not found for email: {email}")

    db_name, db_email, db_password, db_role = user

    # Pass stored_password FIRST, and provided_password SECOND (matching your function definition)
    if not verify_password(db_password, password):
        raise HTTPException(status_code=401, detail="Incorrect password. Access denied.")

    return {
        "message": "Login successful",
        "name": db_name,
        "email": db_email,
        "role": db_role
    }

# =====================================================================
# SPOOF DETECTION ANALYSIS ENDPOINT
# =====================================================================

@app.post("/analyze")
def analyze(req: EmailAnalysisRequest, user_email: str):
    flags = []
    risk_score = 0

    # Protocol checks
    if req.spf_result.lower() in ["fail", "softfail"]:
        risk_score += 30
        flags.append({"category": "Protocol Failure", "severity": "HIGH", "description": "SPF Check Failed"})

    if req.dmarc_result.lower() in ["fail", "none"]:
        risk_score += 25
        flags.append({"category": "Protocol Failure", "severity": "HIGH", "description": "DMARC Check Failed/Missing"})

    if req.dkim_result.lower() == "fail":
        risk_score += 25
        flags.append({"category": "Cryptographic Failure", "severity": "HIGH", "description": "DKIM Signature Invalid"})

    # Header domain mismatch check
    if req.reply_to and req.from_header:
        from_match = re.search(r'@([\w\.-]+)', req.from_header)
        reply_match = re.search(r'@([\w\.-]+)', req.reply_to)
        if from_match and reply_match and from_match.group(1).lower() != reply_match.group(1).lower():
            risk_score += 20
            flags.append({"category": "Header Mismatch", "severity": "MEDIUM", "description": "From and Reply-To domains do not align"})

    risk_score = min(risk_score, 100)
    action = "BLOCK" if risk_score >= 70 else "QUARANTINE" if risk_score >= 45 else "FLAG" if risk_score >= 20 else "ALLOW"

    # Save log tied specifically to the logged-in user's email
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analysis_logs (user_email, from_header, reply_to, risk_score, action)
        VALUES (?, ?, ?, ?, ?)
    """, (user_email.strip().lower(), req.from_header, req.reply_to, risk_score, action))
    conn.commit()
    conn.close()

    return {
        "risk_score": risk_score,
        "action": action,
        "detected_flags": flags
    }