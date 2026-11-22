import os
import re
import json
import time
import hmac
import hashlib
import sqlite3
import jwt
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="Tu Tien Game Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "doi_chuoi_bi_mat_nay_khi_dua_len_server_2026")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_PATH = "game_server.db"

# Danh sách cụm server của game (bạn có thể mở thêm S5, S6... tại đây bất cứ lúc nào)
GAME_SERVERS = [
    {"id": "S1", "name": "S1 - Thạch Hạo", "status": "Mới", "recommended": True},
    {"id": "S2", "name": "S2 - Bổ Thiên Các", "status": "Tốt", "recommended": False},
    {"id": "S3", "name": "S3 - Hư Thần Giới", "status": "Đông", "recommended": False},
    {"id": "S4", "name": "S4 - Thử Nghiệm", "status": "Đông", "recommended": False},
]

login_attempts: dict[str, list[float]] = {}

def dung_postgres() -> bool:
    return DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")

def get_db():
    if dung_postgres():
        url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        return psycopg.connect(url, row_factory=dict_row)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at DOUBLE PRECISION
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS player_saves (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    server_id TEXT NOT NULL,
                    selected_character TEXT DEFAULT 'cha1',
                    level INTEGER DEFAULT 1,
                    vang INTEGER DEFAULT 10000000,
                    da_quy INTEGER DEFAULT 1000000,
                    game_data TEXT DEFAULT '{}',
                    updated_at DOUBLE PRECISION DEFAULT 0,
                    UNIQUE(user_id, server_id)
                )
            """)
        conn.commit()
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS player_saves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                server_id TEXT NOT NULL,
                selected_character TEXT DEFAULT 'cha1',
                level INTEGER DEFAULT 1,
                vang INTEGER DEFAULT 10000000,
                da_quy INTEGER DEFAULT 1000000,
                game_data TEXT DEFAULT '{}',
                updated_at REAL DEFAULT 0,
                UNIQUE(user_id, server_id)
            )
        """)
        conn.commit()
    conn.close()

init_db()

def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return pwd_hash.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    check_hash, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(check_hash, stored_hash)

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

def check_rate_limit(key: str):
    now = time.time()
    history = [t for t in login_attempts.get(key, []) if now - t < 60.0]
    if len(history) >= 5:
        raise HTTPException(status_code=429, detail={"message": "Thử sai quá nhiều lần, vui lòng đợi 1 phút!"})
    history.append(now)
    login_attempts[key] = history

def decode_user_from_header(authorization: str) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"message": "Thiếu token xác thực!"})
    token = authorization.removeprefix("Bearer ").strip()
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail={"message": "Phiên đăng nhập hết hạn hoặc không hợp lệ!"})

def get_or_create_server_save(conn, user_id: int, username: str, server_id: str) -> dict:
    valid_ids = {s["id"] for s in GAME_SERVERS}
    if server_id not in valid_ids:
        raise HTTPException(status_code=400, detail={"message": "Máy chủ không tồn tại!"})

    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM player_saves WHERE user_id = %s AND server_id = %s", (user_id, server_id))
            row = cur.fetchone()
            if row is None:
                now = time.time()
                cur.execute(
                    "INSERT INTO player_saves (user_id, server_id, updated_at) VALUES (%s, %s, %s) RETURNING *",
                    (user_id, server_id, now)
                )
                row = cur.fetchone()
                conn.commit()
    else:
        row = conn.execute("SELECT * FROM player_saves WHERE user_id = ? AND server_id = ?", (user_id, server_id)).fetchone()
        if row is None:
            now = time.time()
            conn.execute(
                "INSERT INTO player_saves (user_id, server_id, updated_at) VALUES (?, ?, ?)",
                (user_id, server_id, now)
            )
            conn.commit()
            row = conn.execute("SELECT * FROM player_saves WHERE user_id = ? AND server_id = ?", (user_id, server_id)).fetchone()

    row_dict = dict(row)
    raw_extra = row_dict.get("game_data") or "{}"
    try:
        extra_dict = json.loads(raw_extra) if isinstance(raw_extra, str) else dict(raw_extra)
    except Exception:
        extra_dict = {}

    return {
        "username": username,
        "server_id": server_id,
        "selected_character": row_dict["selected_character"],
        "level": row_dict["level"],
        "vang": row_dict["vang"],
        "da_quy": row_dict["da_quy"],
        "game_data": extra_dict
    }

class AuthPayload(BaseModel):
    username: str
    password: str

class SyncPayload(BaseModel):
    server_id: str = "S1"
    selected_character: str = "cha1"
    level: int = Field(ge=1, le=9999)
    vang: int = Field(ge=0, le=2_000_000_000)
    da_quy: int = Field(ge=0, le=100_000_000)
    game_data: dict = Field(default_factory=dict)

@app.get("/")
@app.head("/")
def health_check():
    return {
        "status": "online",
        "database": "postgresql" if dung_postgres() else "sqlite",
        "message": "Server game đang hoạt động"
    }

@app.get("/servers")
def list_servers(authorization: str = Header(default="")):
    # Chỉ tính là đã có nhân vật khi người chơi thực sự bấm xác nhận chọn nhân vật (da_chon_nhan_vat = True)
    played_map: dict[str, dict] = {}
    if authorization.startswith("Bearer "):
        try:
            decoded = decode_user_from_header(authorization)
            conn = get_db()
            if dung_postgres():
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT server_id, level, selected_character, game_data FROM player_saves WHERE user_id = %s",
                        (decoded["uid"],)
                    )
                    rows = cur.fetchall()
            else:
                rows = conn.execute(
                    "SELECT server_id, level, selected_character, game_data FROM player_saves WHERE user_id = ?",
                    (decoded["uid"],)
                ).fetchall()
            conn.close()
            for r in rows:
                rd = dict(r)
                raw_extra = rd.get("game_data") or "{}"
                try:
                    extra_dict = json.loads(raw_extra) if isinstance(raw_extra, str) else dict(raw_extra)
                except Exception:
                    extra_dict = {}

                if extra_dict.get("da_chon_nhan_vat") is True:
                    played_map[rd["server_id"]] = {
                        "level": rd["level"],
                        "selected_character": rd["selected_character"]
                    }
        except Exception:
            pass

    result = []
    for sv in GAME_SERVERS:
        item = dict(sv)
        if sv["id"] in played_map:
            item["has_character"] = True
            item["level"] = played_map[sv["id"]]["level"]
        else:
            item["has_character"] = False
            item["level"] = 0
        result.append(item)

    return {"ok": True, "servers": result}

@app.post("/register")
def register(payload: AuthPayload):
    clean_username = payload.username.strip()
    err = validate_username(clean_username)
    if err:
        raise HTTPException(status_code=400, detail={"message": err})
    if len(payload.password) < 4:
        raise HTTPException(status_code=400, detail={"message": "Mật khẩu phải có ít nhất 4 ký tự!"})

    pwd_hash, salt_hex = hash_password(payload.password)
    now = time.time()
    conn = get_db()
    try:
        if dung_postgres():
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                    (clean_username, pwd_hash, salt_hex, now)
                )
                new_uid = cur.fetchone()["id"]
                cur.execute("DELETE FROM player_saves WHERE user_id = %s", (new_uid,))
            conn.commit()
        else:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (clean_username, pwd_hash, salt_hex, now)
            )
            new_uid = cur.lastrowid
            conn.execute("DELETE FROM player_saves WHERE user_id = ?", (new_uid,))
            conn.commit()
    except Exception as e:
        if "unique" in str(e).lower() or "integrity" in str(e).lower():
            raise HTTPException(status_code=409, detail={"message": "Tên đăng nhập đã tồn tại!"})
        raise HTTPException(status_code=500, detail={"message": "Lỗi cơ sở dữ liệu!"})
    finally:
        conn.close()

    return {"ok": True, "message": "Đăng ký thành công!"}

@app.post("/login")
def login(payload: AuthPayload, request: Request):
    clean_username = payload.username.strip()
    rate_key = clean_username.lower() or (request.client.host if request.client else "unknown")
    check_rate_limit(rate_key)

    conn = get_db()
    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (clean_username,))
            row = cur.fetchone()
    else:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (clean_username,)).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail={"message": "Sai tên đăng nhập!"})

    row_dict = dict(row)
    if not verify_password(payload.password, row_dict["password_hash"], row_dict["salt"]):
        raise HTTPException(status_code=401, detail={"message": "Sai mật khẩu!"})

    login_attempts.pop(rate_key, None)

    token = jwt.encode(
        {
            "uid": row_dict["id"],
            "username": row_dict["username"],
            "exp": int(time.time()) + 7 * 86400
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return {
        "ok": True,
        "message": "Đăng nhập thành công!",
        "token": token,
        "username": row_dict["username"]
    }

@app.get("/me")
def get_my_account(authorization: str = Header(default="")):
    decoded = decode_user_from_header(authorization)
    return {"ok": True, "username": decoded["username"]}

@app.get("/character/{server_id}")
def enter_server(server_id: str, authorization: str = Header(default="")):
    decoded = decode_user_from_header(authorization)
    conn = get_db()
    pdata = get_or_create_server_save(conn, decoded["uid"], decoded["username"], server_id)
    conn.close()
    return {"ok": True, "player_data": pdata}

@app.post("/sync")
def sync_player_data(payload: SyncPayload, authorization: str = Header(default="")):
    decoded = decode_user_from_header(authorization)
    uid = decoded["uid"]

    conn = get_db()
    current = get_or_create_server_save(conn, uid, decoded["username"], payload.server_id)

    if payload.vang - current["vang"] > 50_000_000 or payload.da_quy - current["da_quy"] > 500_000:
        conn.close()
        raise HTTPException(status_code=400, detail={"message": "Phát hiện biến động tài nguyên bất thường!"})
    if payload.level < current["level"] or payload.level - current["level"] > 50:
        conn.close()
        raise HTTPException(status_code=400, detail={"message": "Cấp độ không hợp lệ!"})

    extra_json = json.dumps(payload.game_data, ensure_ascii=False)
    now = time.time()

    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE player_saves
                SET selected_character = %s, level = %s, vang = %s, da_quy = %s, game_data = %s, updated_at = %s
                WHERE user_id = %s AND server_id = %s
                """,
                (payload.selected_character, payload.level, payload.vang, payload.da_quy, extra_json, now, uid, payload.server_id)
            )
        conn.commit()
    else:
        conn.execute(
            """
            UPDATE player_saves
            SET selected_character = ?, level = ?, vang = ?, da_quy = ?, game_data = ?, updated_at = ?
            WHERE user_id = ? AND server_id = ?
            """,
            (payload.selected_character, payload.level, payload.vang, payload.da_quy, extra_json, now, uid, payload.server_id)
        )
        conn.commit()
    conn.close()

    return {"ok": True, "message": "Đã đồng bộ dữ liệu lên máy chủ!", "updated_at": now}
