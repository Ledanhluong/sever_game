import os
import re
import time
import hmac
import hashlib
import sqlite3
import jwt
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Tu Tien Game Backend")

# Cho phép Web export / Mobile gọi API không bị chặn CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "doi_chuoi_bi_mat_nay_khi_dua_len_server_2026")
DB_PATH = "game_server.db"

# Bộ nhớ đệm chống spam đăng nhập (IP -> danh sách timestamp)
login_attempts: dict[str, list[float]] = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            selected_character TEXT DEFAULT 'cha1',
            level INTEGER DEFAULT 1,
            vang INTEGER DEFAULT 1000,
            da_quy INTEGER DEFAULT 100,
            created_at REAL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Hàm băm & kiểm tra mật khẩu an toàn ---
def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return pwd_hash.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    check_hash, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(check_hash, stored_hash)

# --- Kiểm tra tên đăng nhập khớp luật Godot (có cả chữ và số, không dấu cách) ---
def validate_username(username: str) -> str | None:
    if not username:
        return "Tên đăng nhập không được để trống!"
    if " " in username:
        return "Tên đăng nhập không được chứa dấu cách!"
    if not re.fullmatch(r"[A-Za-z0-9]+", username):
        return "Tên đăng nhập chỉ được gồm chữ và số, không dấu cách!"
    if not (re.search(r"[A-Za-z]", username) and re.search(r"[0-9]", username)):
        return "Tên đăng nhập phải bao gồm cả chữ và số!"
    if len(username) < 4 or len(username) > 24:
        return "Tên đăng nhập phải từ 4 đến 24 ký tự!"
    return None

# --- Chống spam đăng nhập (tối đa 5 lần / 60 giây) ---
def check_rate_limit(client_ip: str):
    now = time.time()
    history = [t for t in login_attempts.get(client_ip, []) if now - t < 60.0]
    if len(history) >= 5:
        raise HTTPException(status_code=429, detail={"message": "Thử sai quá nhiều lần, vui lòng đợi 1 phút!"})
    history.append(now)
    login_attempts[client_ip] = history

class AuthPayload(BaseModel):
    username: str
    password: str

@app.get("/")
def health_check():
    return {"status": "online", "message": "Server game đang hoạt động"}

@app.post("/register")
def register(payload: AuthPayload):
    err = validate_username(payload.username)
    if err:
        raise HTTPException(status_code=400, detail={"message": err})
    if len(payload.password) < 4:
        raise HTTPException(status_code=400, detail={"message": "Mật khẩu phải có ít nhất 4 ký tự!"})

    pwd_hash, salt_hex = hash_password(payload.password)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            (payload.username, pwd_hash, salt_hex, time.time())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail={"message": "Tên đăng nhập đã tồn tại!"})
    finally:
        conn.close()

    return {"ok": True, "message": "Đăng ký thành công!"}

@app.post("/login")
def login(payload: AuthPayload, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (payload.username,)).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail={"message": "Sai tên đăng nhập!"})

    if not verify_password(payload.password, row["password_hash"], row["salt"]):
        raise HTTPException(status_code=401, detail={"message": "Sai mật khẩu!"})

    # Xóa lịch sử thử sai khi đăng nhập thành công
    login_attempts.pop(client_ip, None)

    # Tạo Token xác thực có hiệu lực 7 ngày
    token = jwt.encode(
        {
            "uid": row["id"],
            "username": row["username"],
            "exp": int(time.time()) + 7 * 86400
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return {
        "ok": True,
        "message": "Đăng nhập thành công!",
        "token": token,
        "player_data": {
            "username": row["username"],
            "selected_character": row["selected_character"],
            "level": row["level"],
            "vang": row["vang"],
            "da_quy": row["da_quy"]
        }
    }

# --- Endpoint mẫu có kiểm tra Token chống giả mạo ---
@app.get("/me")
def get_my_profile(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"message": "Thiếu token xác thực!"})
    token = authorization.removeprefix("Bearer ").strip()
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail={"message": "Phiên đăng nhập hết hạn hoặc không hợp lệ!"})

    conn = get_db()
    row = conn.execute(
        "SELECT username, selected_character, level, vang, da_quy FROM users WHERE id = ?",
        (decoded["uid"],)
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail={"message": "Không tìm thấy người chơi!"})

    return {"ok": True, "player_data": dict(row)}