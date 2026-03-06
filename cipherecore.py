import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog, colorchooser, simpledialog
import re
import socket
import threading
import hashlib
import base64
import os
import json
import random
import string
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import time
import qrcode
from io import BytesIO
from PIL import Image, ImageTk
from collections import deque
import webbrowser
import uuid
import sqlite3
import ssl
import hmac
from typing import Optional, Dict, List, Tuple, Any
import bcrypt
from dotenv import load_dotenv
import sys

# --- ASSET PATH HELPER ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)

# Load environment variables from .env file (must happen before constants are read)
load_dotenv(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".env"))

try:
    import pymongo
    from pymongo import MongoClient
except ImportError:
    pymongo = None

# ========== CONFIGURATION CONSTANTS ==========
CONFIG_FILE = "config.json"
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "system.log")
DATABASE_FILE = os.path.join(BASE_DIR, "ciphercore.db")
CERTS_DIR = os.path.join(BASE_DIR, "certs")
DEFAULT_PORT = 5000
MESSAGE_DEDUP_TIMEOUT = 3.0
MAX_RECENT_MESSAGES = 200
MAX_TEXT_SIZE = 1_000_000  # 1MB in characters
MAX_FILE_SIZE = 500_000_000  # 500MB in bytes
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_DURATION = 300  # 5 minutes
RATE_LIMIT_THRESHOLD = 10  # messages per minute
MESSAGE_MAX_SIZE = 65536  # 64KB per message
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "ciphercore")
# ========== UI COLOR CONSTANTS ==========
BG_COLOR = "#080B10"           # Deeper black
HEADER_COLOR = "#0D1117"
ACCENT_CYAN = "#00D4FF"
ACCENT_BLUE = "#3498DB"
ACCENT_PURPLE = "#A855F7"      # New accent color
TEXT_COLOR = "#FFFFFF"
SUBTEXT_COLOR = "#94A3B8"      # Balanced blue-gray
BORDER_COLOR = "#1E293B"       # Subtler border
SUCCESS_GREEN = "#10B981"
DANGER_RED = "#EF4444"
WARNING_ORANGE = "#F59E0B"
CARD_BG = "#111827"
GLOW_COLOR = "#1D4ED8"         # Subtle blue glow

SOCKET_TIMEOUT = 30
IDLE_TIMEOUT = 600  # 10 minutes

try:
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)
except PermissionError:
    # Fallback to a per-user directory if creating in the script directory is denied
    fallback_base = os.path.join(os.path.expanduser("~"), ".ciphercore")
    fallback_logs = os.path.join(fallback_base, "logs")
    fallback_certs = os.path.join(fallback_base, "certs")
    os.makedirs(fallback_logs, exist_ok=True)
    os.makedirs(fallback_certs, exist_ok=True)
    LOG_FILE = os.path.join(fallback_logs, "system.log")
    DATABASE_FILE = os.path.join(fallback_base, "ciphercore.db")
    CERTS_DIR = fallback_certs

# ========== DATABASE INITIALIZATION ==========
def init_database() -> None:
    """Initialize SQLite database with proper schema"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )''')
    
    # Messages table with integrity
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        recipient_id INTEGER,
        channel TEXT,
        content TEXT NOT NULL,
        encrypted BOOLEAN DEFAULT 0,
        cipher_type TEXT,
        hmac TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_deleted BOOLEAN DEFAULT 0,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
    )''')
    
    # Sessions table
    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_token TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        ip_address TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Channels table
    cursor.execute('''CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        owner_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )''')
    
    # Rate limiting
    cursor.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()

# ========== INPUT VALIDATION ==========
def validate_username(username: str) -> Tuple[bool, str]:
    """Validate username format and length"""
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 32:
        return False, "Username must be at most 32 characters"
    if not all(c.isalnum() or c in '-_' for c in username):
        return False, "Username can only contain letters, numbers, hyphens, and underscores"
    return True, ""

def validate_email(email: str) -> Tuple[bool, str]:
    """Validate email format"""
    if not email:
        return True, ""  # Optional field
    if len(email) > 254 or '@' not in email:
        return False, "Invalid email format"
    return True, ""

def validate_message(message: str) -> Tuple[bool, str]:
    """Validate message content"""
    if not message or not message.strip():
        return False, "Message cannot be empty"
    if len(message) > MESSAGE_MAX_SIZE:
        return False, f"Message exceeds maximum size of {MESSAGE_MAX_SIZE} bytes"
    return True, ""

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input to prevent injection"""
    if not isinstance(text, str):
        return ""
    return text.strip()[:max_length]

# ========== ENCRYPTION FUNCTIONS ==========
def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password - no restrictions, any password is allowed"""
    return True, ""

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    if not password:
        password = secrets.token_hex(16)
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), password_hash.encode())

def generate_random_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password"""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def check_password_strength(password: str) -> Tuple[int, List[str]]:
    """Evaluate password strength and provide feedback"""
    score = 0
    feedback = []
    
    if len(password) >= 8: 
        score += 1
    else: 
        feedback.append("Use at least 8 characters")
    
    if any(c.islower() for c in password) and any(c.isupper() for c in password): 
        score += 1
    else: 
        feedback.append("Mix uppercase and lowercase")
    
    if any(c.isdigit() for c in password): 
        score += 1
    else: 
        feedback.append("Add numbers")
    
    if any(c in string.punctuation for c in password): 
        score += 1
    else: 
        feedback.append("Add special characters")
    
    if len(password) >= 12: 
        score += 1
    
    return min(score, 5), feedback

def generate_session_token() -> str:
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    """Derive encryption key using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode())

def sha256_key(password: str) -> bytes:
    """Generate SHA-256 hash key from password"""
    return hashlib.sha256(password.encode()).digest()

def fernet_key_from_bytes(key_bytes: bytes) -> bytes:
    """Convert bytes to Fernet-compatible key"""
    return base64.urlsafe_b64encode(key_bytes)

def compute_message_hmac(message: str, key: str) -> str:
    """Compute HMAC for message integrity verification"""
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

def verify_message_hmac(message: str, message_hmac: str, key: str) -> bool:
    """Verify message HMAC"""
    expected_hmac = compute_message_hmac(message, key)
    return hmac.compare_digest(expected_hmac, message_hmac)

def encrypt_fernet(text: str, password: str) -> str:
    """Encrypt text using Fernet (symmetric encryption)"""
    key = sha256_key(password)
    f = Fernet(fernet_key_from_bytes(key))
    return f.encrypt(text.encode()).decode()

def decrypt_fernet(encrypted_text: str, password: str) -> str:
    """Decrypt Fernet encrypted text"""
    key = sha256_key(password)
    f = Fernet(fernet_key_from_bytes(key))
    return f.decrypt(encrypted_text.encode()).decode()

def encrypt_aes(text: str, password: str) -> str:
    """Encrypt text using AES-256 in CBC mode"""
    key = sha256_key(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_aes(encrypted_text: str, password: str) -> str:
    """Decrypt AES encrypted text"""
    try:
        data = base64.b64decode(encrypted_text.encode())
        iv, encrypted = data[:16], data[16:]
        key = sha256_key(password)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted.decode()
    except Exception as e:
        raise Exception("Decryption failed - wrong password or corrupt data")

def encrypt_rc4(text: str, password: str) -> str:
    """Encrypt text using RC4 stream cipher (AES-CTR)"""
    key = hashlib.md5(password.encode()).digest()[:16]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_rc4(encrypted_text: str, password: str) -> str:
    """Decrypt RC4 encrypted text"""
    try:
        data = base64.b64decode(encrypted_text.encode())
        iv, encrypted = data[:16], data[16:]
        key = hashlib.md5(password.encode()).digest()[:16]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted).decode() + decryptor.finalize().decode()
    except Exception:
        raise Exception("Decryption failed - wrong password or corrupt data")

def encrypt_triple_des(text: str, password: str) -> str:
    """Encrypt text using Triple DES"""
    key = hashlib.sha256(password.encode()).digest()[:24]
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_triple_des(encrypted_text: str, password: str) -> str:
    """Decrypt Triple DES encrypted text"""
    try:
        data = base64.b64decode(encrypted_text.encode())
        iv, encrypted = data[:8], data[8:]
        key = hashlib.sha256(password.encode()).digest()[:24]
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted.decode()
    except Exception:
        raise Exception("Decryption failed - wrong password or corrupt data")

def encrypt_chacha20(text: str, password: str) -> str:
    """Encrypt text using ChaCha20 stream cipher"""
    key = hashlib.sha256(password.encode()).digest()
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + encrypted).decode()

def decrypt_chacha20(encrypted_text: str, password: str) -> str:
    """Decrypt ChaCha20 encrypted text"""
    try:
        data = base64.b64decode(encrypted_text.encode())
        nonce, encrypted = data[:12], data[12:]
        key = hashlib.sha256(password.encode()).digest()
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted).decode() + decryptor.finalize().decode()
    except Exception:
        raise Exception("Decryption failed - wrong password or corrupt data")

# ========== USER AUTHENTICATION & DATABASE SYSTEM ==========
class UserManager:
    """Manage user authentication and profiles with database persistence"""
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.login_attempts: Dict[str, Tuple[int, float]] = {}  # username -> (attempts, timestamp)
        
    def register_user(self, username: str, password: str, email: str = "") -> Tuple[bool, str]:
        """Register a new user with validation"""
        # Validate input
        valid, msg = validate_username(username)
        if not valid:
            return False, msg
            
        valid, msg = validate_email(email)
        if not valid:
            return False, msg
        
        if not password:
            return False, "Password cannot be empty"
        
        # Check if user exists
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return False, "Username already exists"
        
        # Hash password and insert user
        password_hash = hash_password(password)
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, password_hash, email)
            )
            conn.commit()
            conn.close()
            return True, "User registered successfully"
        except sqlite3.Error as e:
            conn.close()
            return False, f"Registration error: {str(e)}"
    
    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[str]]:
        """Login user with rate limiting and return session token"""
        # Check rate limiting
        if username in self.login_attempts:
            attempts, last_time = self.login_attempts[username]
            if attempts >= MAX_LOGIN_ATTEMPTS:
                if time.time() - last_time < LOGIN_LOCKOUT_DURATION:
                    return False, "Account locked. Try again later", None
                else:
                    del self.login_attempts[username]
            else:
                self.login_attempts[username] = (attempts + 1, last_time)
        
        # Check credentials
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username = ? AND is_active = 1", (username,))
        result = cursor.fetchone()
        
        if not result or not verify_password(password, result[1]):
            if username not in self.login_attempts:
                self.login_attempts[username] = (1, time.time())
            conn.close()
            return False, "Invalid username or password", None
        
        # Clear login attempts and create session
        if username in self.login_attempts:
            del self.login_attempts[username]
        
        user_id = result[0]
        session_token = generate_session_token()
        expires_at = datetime.now() + timedelta(hours=24)
        
        cursor.execute(
            "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
            (user_id, session_token, expires_at)
        )
        cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now(), user_id))
        conn.commit()
        conn.close()
        
        return True, "Login successful", session_token
    
    def get_user_by_token(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Get user info by session token"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.expires_at > datetime('now')
        ''', (session_token,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {"id": result[0], "username": result[1], "email": result[2]}
        return None
    
    def logout(self, session_token: str) -> bool:
        """Logout user by invalidating session"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
        conn.commit()
        conn.close()
        return True

class MongoManager:
    """Manager for MongoDB persistence"""
    def __init__(self, uri, db_name):
        self.uri = uri
        self.db_name = db_name
        self.client = None
        self.db = None
        self.connected = False
        self.connect()

    def connect(self):
        if not pymongo: 
            self.last_error = "pymongo library not installed"
            return False
        
        # Try primary URI
        try:
            self.client = MongoClient(self.uri, serverSelectionTimeoutMS=2000)
            self.db = self.client[self.db_name]
            self.client.server_info()
            self.connected = True
            self.init_collections()
            return True
        except Exception as e:
            # Fallback to localhost string if primary fails
            try:
                self.client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
                self.db = self.client[self.db_name]
                self.client.server_info()
                self.connected = True
                self.init_collections()
                return True
            except Exception:
                self.last_error = str(e)
                self.connected = False
                return False

    def init_collections(self):
        """Initialize all required collections and indexes"""
        if not self.connected:
            return

        existing = self.db.list_collection_names()

        # ── users ──────────────────────────────────────────────────────────
        if "users" not in existing:
            self.db.create_collection("users")
        self.db.users.create_index("username", unique=True, background=True)

        # ── social (friends / friend-requests) ────────────────────────────
        if "social" not in existing:
            self.db.create_collection("social")
        self.db.social.create_index("username", unique=True, background=True)

        # ── logs (server-side event / error logs) ─────────────────────────
        # Schema: { level, source, message, user, timestamp }
        if "logs" not in existing:
            self.db.create_collection("logs")
        self.db.logs.create_index("timestamp", background=True)
        self.db.logs.create_index("level",     background=True)
        self.db.logs.create_index("source",    background=True)

        # ── server_chat (per-server channel messages) ─────────────────────
        # Schema: { server_id, channel, sender, content, timestamp }
        if "server_chat" not in existing:
            self.db.create_collection("server_chat")
        self.db.server_chat.create_index(
            [("server_id", 1), ("channel", 1), ("timestamp", 1)], background=True
        )
        self.db.server_chat.create_index("sender", background=True)

        # ── global_chat (public broadcast messages) ───────────────────────
        # Schema: { sender, content, timestamp }
        if "global_chat" not in existing:
            self.db.create_collection("global_chat")
        self.db.global_chat.create_index("timestamp", background=True)
        self.db.global_chat.create_index("sender",    background=True)

        # ── private_chat (1-to-1 direct messages) ─────────────────────────
        # Schema: { sender, recipient, content, timestamp }
        # Compound index covers both directions of a DM conversation
        if "private_chat" not in existing:
            self.db.create_collection("private_chat")
        self.db.private_chat.create_index(
            [("sender", 1), ("recipient", 1), ("timestamp", 1)], background=True
        )
        self.db.private_chat.create_index("timestamp", background=True)

    def register(self, username, password, email=""):
        if not self.connected: return False, "MongoDB not connected"
        try:
            if self.db.users.find_one({"username": username}):
                return False, "Username already exists"
            
            user_data = {
                "username": username,
                "password_hash": hash_password(password),
                "email": email,
                "friends": [],
                "created_at": datetime.now()
            }
            self.db.users.insert_one(user_data)
            self.db.social.insert_one({"username": username, "friends": [], "requests": []})
            return True, "Registered in MongoDB"
        except Exception as e:
            return False, str(e)

    def login(self, username, password):
        if not self.connected: return False, "MongoDB not connected", None
        try:
            user = self.db.users.find_one({"username": username})
            if user and verify_password(password, user["password_hash"]):
                return True, "Login successful", user
            return False, "Invalid credentials", None
        except Exception as e:
            return False, str(e), None

    def get_friends(self, username):
        if not self.connected: return []
        social = self.db.social.find_one({"username": username})
        return social.get("friends", []) if social else []

    def add_friend(self, username, friend_name):
        if not self.connected: return False
        # Check if friend exists
        if not self.db.users.find_one({"username": friend_name}):
            return False
        self.db.social.update_one({"username": username}, {"$addToSet": {"friends": friend_name}})
        self.db.social.update_one({"username": friend_name}, {"$addToSet": {"friends": username}})
        return True

    # ── LOGS ──────────────────────────────────────────────────────────────
    def save_log(self, message: str, level: str = "INFO",
                 source: str = "server", user: str = "SYSTEM") -> bool:
        """Persist a log entry to the logs collection.

        Args:
            message: Human-readable log message.
            level:   Severity — INFO | WARNING | ERROR | DEBUG.
            source:  Component that generated the log (e.g. 'server', 'auth').
            user:    Username associated with the event.
        """
        if not self.connected:
            return False
        try:
            self.db.logs.insert_one({
                "level":     level.upper(),
                "source":    source,
                "message":   message,
                "user":      user,
                "timestamp": datetime.now()
            })
            return True
        except Exception:
            return False

    def get_logs(self, level: str = None, source: str = None,
                 limit: int = 100) -> list:
        """Retrieve log entries, optionally filtered by level and/or source."""
        if not self.connected:
            return []
        query = {}
        if level:
            query["level"] = level.upper()
        if source:
            query["source"] = source
        cursor = self.db.logs.find(query).sort("timestamp", -1).limit(limit)
        return list(cursor)[::-1]

    # ── SERVER CHAT ────────────────────────────────────────────────────────
    def save_server_message(self, server_id: str, channel: str,
                            sender: str, content: str) -> bool:
        """Save a message sent inside a server channel."""
        if not self.connected:
            return False
        try:
            self.db.server_chat.insert_one({
                "server_id": server_id,
                "channel":   channel,
                "sender":    sender,
                "content":   content,
                "timestamp": datetime.now()
            })
            return True
        except Exception:
            return False

    def get_server_messages(self, server_id: str, channel: str,
                            limit: int = 50) -> list:
        """Retrieve the latest messages for a server channel."""
        if not self.connected:
            return []
        cursor = (
            self.db.server_chat
            .find({"server_id": server_id, "channel": channel})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return list(cursor)[::-1]

    # ── GLOBAL CHAT ────────────────────────────────────────────────────────
    def save_global_message(self, sender: str, content: str) -> bool:
        """Save a public global-chat message."""
        if not self.connected:
            return False
        try:
            self.db.global_chat.insert_one({
                "sender":    sender,
                "content":   content,
                "timestamp": datetime.now()
            })
            return True
        except Exception:
            return False

    def get_global_messages(self, limit: int = 50) -> list:
        """Retrieve the latest global-chat messages."""
        if not self.connected:
            return []
        cursor = (
            self.db.global_chat
            .find()
            .sort("timestamp", -1)
            .limit(limit)
        )
        return list(cursor)[::-1]

    # ── PRIVATE CHAT ───────────────────────────────────────────────────────
    def save_private_message(self, sender: str, recipient: str,
                             content: str) -> bool:
        """Save a private (DM) message between two users."""
        if not self.connected:
            return False
        try:
            self.db.private_chat.insert_one({
                "sender":    sender,
                "recipient": recipient,
                "content":   content,
                "timestamp": datetime.now()
            })
            return True
        except Exception:
            return False

    def get_private_messages(self, user_a: str, user_b: str,
                             limit: int = 80) -> list:
        """Retrieve the DM history between two users (both directions)."""
        if not self.connected:
            return []
        query = {
            "$or": [
                {"sender": user_a, "recipient": user_b},
                {"sender": user_b, "recipient": user_a},
            ]
        }
        cursor = (
            self.db.private_chat
            .find(query)
            .sort("timestamp", -1)
            .limit(limit)
        )
        return list(cursor)[::-1]

    # ── FRIEND REQUESTS ───────────────────────────────────────────────────
    def send_friend_request(self, from_user: str, to_user: str) -> tuple:
        """Send a friend request from from_user to to_user."""
        if not self.connected:
            return False, "MongoDB not connected"
        if not self.db.users.find_one({"username": to_user}):
            return False, "User not found"
        if from_user == to_user:
            return False, "Cannot add yourself"
        # Check already friends
        social = self.db.social.find_one({"username": from_user})
        if social and to_user in social.get("friends", []):
            return False, "Already friends"
        # Check duplicate pending request
        existing = self.db.social.find_one(
            {"username": to_user, "requests": {"$elemMatch": {"from": from_user, "status": "pending"}}}
        )
        if existing:
            return False, "Request already sent"
        self.db.social.update_one(
            {"username": to_user},
            {"$push": {"requests": {"from": from_user, "status": "pending", "ts": datetime.now()}}},
            upsert=True
        )
        return True, "Friend request sent"

    def get_pending_requests(self, username: str) -> list:
        """Return list of pending incoming friend request usernames."""
        if not self.connected:
            return []
        social = self.db.social.find_one({"username": username})
        if not social:
            return []
        return [r["from"] for r in social.get("requests", []) if r.get("status") == "pending"]

    def respond_friend_request(self, username: str, from_user: str, accept: bool) -> bool:
        """Accept or decline a pending friend request."""
        if not self.connected:
            return False
        new_status = "accepted" if accept else "declined"
        self.db.social.update_one(
            {"username": username, "requests.from": from_user},
            {"$set": {"requests.$.status": new_status}}
        )
        if accept:
            self.db.social.update_one({"username": username}, {"$addToSet": {"friends": from_user}}, upsert=True)
            self.db.social.update_one({"username": from_user}, {"$addToSet": {"friends": username}}, upsert=True)
        return True


class MessageStore:
    """Store and retrieve messages with integrity checks"""
    def __init__(self):
        self.db_file = DATABASE_FILE
    
    def save_message(self, sender_id: int, channel: str, content: str, 
                    encrypted: bool = False, cipher_type: str = "", hmac_value: str = "") -> Tuple[bool, str]:
        """Save message to database with optional encryption and HMAC"""
        # Validate message
        valid, msg = validate_message(content)
        if not valid:
            return False, msg
        
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (sender_id, channel, content, encrypted, cipher_type, hmac)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (sender_id, channel, content, encrypted, cipher_type, hmac_value))
            conn.commit()
            conn.close()
            return True, "Message saved"
        except sqlite3.Error as e:
            return False, f"Database error: {str(e)}"
    
    def get_channel_messages(self, channel: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get messages for a channel"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT m.id, u.username, m.content, m.encrypted, m.cipher_type, m.created_at, m.hmac
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.channel = ? AND m.is_deleted = 0
            ORDER BY m.created_at DESC
            LIMIT ?
        ''', (channel, limit))
        
        messages = []
        for row in cursor.fetchall():
            messages.append({
                "id": row[0],
                "sender": row[1],
                "content": row[2],
                "encrypted": row[3],
                "cipher_type": row[4],
                "timestamp": row[5],
                "hmac": row[6]
            })
        conn.close()
        return list(reversed(messages))

class RateLimiter:
    """Rate limiting to prevent spam/DoS"""
    def __init__(self):
        self.db_file = DATABASE_FILE
    
    def check_rate_limit(self, user_id: int, action: str = "message") -> Tuple[bool, str]:
        """Check if user has exceeded rate limit"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get count of actions in last minute
        one_minute_ago = datetime.now() - timedelta(minutes=1)
        cursor.execute('''
            SELECT COUNT(*) FROM rate_limits
            WHERE user_id = ? AND action = ? AND timestamp > ?
        ''', (user_id, action, one_minute_ago))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        if count >= RATE_LIMIT_THRESHOLD:
            return False, f"Rate limit exceeded. Max {RATE_LIMIT_THRESHOLD} {action}s per minute"
        
        # Log the action
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO rate_limits (user_id, action) VALUES (?, ?)",
            (user_id, action)
        )
        conn.commit()
        conn.close()
        
        return True, ""

# ========== LOGGING SYSTEM ==========
class Logger:
    """Comprehensive logging system for tracking events"""
    def __init__(self):
        self.logs = []
        self.load_logs()
        
    def load_logs(self):

        try:
            if os.path.exists(LOG_FILE):
                file_size = os.path.getsize(LOG_FILE)
                if file_size > 0:
                    with open(LOG_FILE, 'r') as f:
                        self.logs = json.load(f)
                else:
                    self.logs = []
        except (json.JSONDecodeError, IOError, ValueError):
            # File exists but is empty or corrupted - start fresh
            self.logs = []
            
    def save_logs(self):
        try:
            with open(LOG_FILE, 'w') as f:
                json.dump(self.logs[-500:], f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save logs: {e}")
            
    def log(self, log_type, message, user="SYSTEM"):
        log_entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': log_type,
            'message': message,
            'user': user
        }
        self.logs.append(log_entry)
        self.save_logs()
        
    def get_logs(self, count=50):
        return self.logs[-count:]

# ========== CHAT CLIENT ==========
class ChatClient:
    """Client for connecting to chat server"""
    def __init__(self, gui, host, port, nickname, password=""):
        self.gui = gui
        self.host = host
        self.port = port
        self.nickname = nickname
        self.password = password
        self.socket = None
        self.running = False
        self.connect()
        
    def connect(self):
        max_retries = 3
        retry_delay = 0.5
        
        for attempt in range(max_retries):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(SOCKET_TIMEOUT)
                self.socket.connect((self.host, self.port))
                self.running = True
                
                # Send password for authentication (plain or encrypted)
                if self.password:
                    auth_data = f"AUTH:{self.password}"
                else:
                    auth_data = f"AUTH:"
                
                self.socket.send(auth_data.encode())
                
                # Wait for authentication response
                auth_response = self.socket.recv(4096).decode()
                if not auth_response.startswith("AUTH_SUCCESS"):
                    error_msg = auth_response.split(":", 1)[1] if ":" in auth_response else "Unknown error"
                    self.gui.chat_add(f"❌ Authentication failed: {error_msg}", "error")
                    self.socket.close()
                    self.running = False
                    return
                
                # Send nickname after successful authentication
                nick_data = f"NICK:{self.nickname}"
                self.socket.send(nick_data.encode())
                
                threading.Thread(target=self.receive_messages, daemon=True).start()
                return # Connection successful
                
            except socket.error as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                self.gui.chat_add(f"❌ Connection attempt {attempt+1} failed: {str(e)}", "error")
                if attempt == max_retries - 1:
                    self.gui.chat_add(f"❌ Final connection failed. Is the server running?", "error")
            
    def receive_messages(self):
        while self.running:
            try:
                if self.socket is None:
                    break
                data = self.socket.recv(4096)
                if not data:
                    break
                decoded_data = data.decode()
                if decoded_data.strip():  # Only display non-empty messages
                    # Always check if it looks encrypted so we can toggle it later
                    encrypted_content = ""
                    if self.gui._looks_encrypted(decoded_data):
                        encrypted_content = decoded_data
                    
                    self.gui.chat_add(decoded_data, "message", encrypted_content=encrypted_content)
            except socket.timeout:
                # Timeout is normal, just continue waiting
                if self.running:
                    continue
                else:
                    break
            except socket.error:
                break
                
        if self.running:  # Only show if we didn't disconnect voluntarily
            self.running = False
            self.gui.status_label.configure(text="🔴 Disconnected")
            
    def send_message(self, message):
        if self.socket and self.running:
            try:
                self.socket.send(message.encode())
            except socket.timeout:
                # Timeout on send is usually ok, message may have queued
                pass
            except socket.error as e:
                self.running = False
                self.gui.chat_add("❌ Connection lost while sending", "error")
                self.gui.status_label.configure(text="🔴 Disconnected")
                
    def disconnect(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except socket.error:
                pass

# ========== CHAT SERVER ==========
class ChatServer:
    """Server for hosting chat rooms with secure session-based authentication and persistence"""
    def __init__(self, gui, port=5000, password=""):
        self.gui = gui
        self.port = port
        self.socket = None
        self.running = False
        self.clients: Dict[socket.socket, Dict[str, Any]] = {}
        self.server_password = password
        # Generate server encryption key from password
        self.server_key = Fernet(fernet_key_from_bytes(sha256_key(password))) if password else None
        self.stats = {
            'total_messages': 0,
            'total_clients': 0,
            'start_time': datetime.now()
        }
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.running = True
            
            self.gui.logger.log("SERVER_STARTED", f"Server started on port {self.port}")
            self.gui.chat_add(f"🖥️ Server started on port {self.port}", "system")
            
            threading.Thread(target=self.accept_clients, daemon=True).start()
            return True
        except socket.error as e:
            self.gui.chat_add(f"❌ Failed to start server: {str(e)}", "error")
            return False
            
    def accept_clients(self):
        while self.running:
            try:
                if self.socket is None:
                    break
                client_socket, address = self.socket.accept()
                client_thread = threading.Thread(target=self.handle_client, 
                                               args=(client_socket, address), daemon=True)
                client_thread.start()
            except socket.error:
                break
                
    def handle_client(self, client_socket, address):
        client_id = f"{address[0]}:{address[1]}"
        client_socket.settimeout(SOCKET_TIMEOUT)
        
        # Authenticate with password
        authenticated = False
        try:
            auth_msg = client_socket.recv(4096).decode()
            
            if auth_msg.startswith("AUTH:"):
                received_pwd = auth_msg.split(":", 1)[1]
                try:
                    # Compare password directly
                    if self.server_password:
                        if received_pwd == self.server_password:
                            authenticated = True
                            client_socket.send("AUTH_SUCCESS".encode())
                        else:
                            client_socket.send("AUTH_FAILED:Wrong password".encode())
                    else:
                        # No server password set - allow connection
                        authenticated = True
                        client_socket.send("AUTH_SUCCESS".encode())
                except Exception as e:
                    client_socket.send(f"AUTH_FAILED:{str(e)}".encode())
            else:
                client_socket.send("AUTH_FAILED:Invalid auth format".encode())
                
        except socket.error:
            return
        
        if not authenticated:
            try:
                client_socket.close()
            except socket.error:
                pass
            self.gui.chat_add(f"🔌 Connection rejected from {client_id} - authentication failed", "error")
            return
        
        self.clients[client_socket] = {
            'address': address,
            'nickname': f"User{len(self.clients)}",
            'join_time': datetime.now(),
            'messages_sent': 0
        }
        
        self.stats['total_clients'] += 1
        self.gui.chat_add(f"🔗 New connection from {client_id} (authenticated)", "system")
        
        try:
            while self.running:
                try:
                    data = client_socket.recv(4096).decode()
                    if not data:
                        break
                        
                    if data.startswith("NICK:"):
                        nickname = data.split(":", 1)[1]
                        self.clients[client_socket]['nickname'] = nickname
                        self.gui.chat_add(f"✅ {nickname} joined the chat", "system")
                        # Broadcast only to OTHER clients, not the sender
                        self.broadcast(f"👋 {nickname} joined the chat", exclude=client_socket)
                    else:
                        self.handle_message(client_socket, data)
                except socket.timeout:
                    continue
                except socket.error as e:
                    break
                    
        except socket.error:
            pass
        finally:
            self.remove_client(client_socket, address)
            try:
                client_socket.close()
            except socket.error:
                pass
            
    def handle_message(self, client_socket, message):
        nick = self.clients[client_socket]['nickname']
        self.clients[client_socket]['messages_sent'] += 1
        self.stats['total_messages'] += 1
        
        formatted_msg = f"{nick}: {message}"
        # Log message but don't display in server's chat (only broadcast to clients)
        self.gui.logger.log("MESSAGE_RECEIVED", f"{nick}: {message}")
        # Broadcast only to OTHER clients, not the sender
        self.broadcast(formatted_msg, exclude=client_socket)
        
    def broadcast(self, message, exclude=None):
        for client_sock in list(self.clients.keys()):
            if client_sock != exclude:
                try:
                    client_sock.send(message.encode())
                except socket.error:
                    self.remove_client(client_sock, self.clients[client_sock]['address'])
                    
    def remove_client(self, client_socket: socket.socket, address) -> None:
        """Remove disconnected client"""
        if client_socket in self.clients:
            client_info = self.clients[client_socket]
            nick = client_info.get('nickname', 'Unknown')
            del self.clients[client_socket]
            self.gui.chat_add(f"🔌 {nick} disconnected", "system")
            self.broadcast(f"👋 {nick} left the chat", exclude=client_socket)
        
    def stop(self):
        self.running = False
        for client_sock in list(self.clients.keys()):
            try:
                client_sock.close()
            except socket.error:
                pass
        if self.socket:
            try:
                self.socket.close()
            except socket.error:
                pass
        self.clients.clear()

# ========== MAIN APPLICATION ==========
class CipherCoreApp(ctk.CTk):
    """Main application class for CipherCore"""
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("CipherCore - Multi-Purpose Security Platform")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.minsize(800, 600)
        
        # Set window icon
        try:
            icon_path = os.path.join(os.path.dirname(__file__), "ciphercore_icon.ico")
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
        except Exception as e:
            print(f"Warning: Could not set window icon: {e}")
        
        # Initialize database and security components
        try:
            init_database()
        except Exception as e:
            print(f"Warning: Database initialization failed: {e}")
        
        # Initialize components
        self.logger = Logger()
        self.user_manager: Optional[UserManager] = None
        self.message_store: Optional[MessageStore] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.current_user: Optional[Dict[str, Any]] = None
        self.current_session_token: Optional[str] = None
        
        try:
            self.user_manager = UserManager()
            self.message_store = MessageStore()
            self.rate_limiter = RateLimiter()
            self.mongo_manager = MongoManager(MONGO_URI, MONGO_DB_NAME)
        except Exception as e:
            self.logger.log("ERROR", f"Failed to initialize security managers: {e}")
            self.mongo_manager = None
        
        self.client = None
        self.server = None
        self.message_encryption_enabled = False
        self.message_decryption_enabled = False
        self.bubble_mode_enabled = False # Toggle for terminal vs modern chat bubbles
        self.message_encryption_password = ""
        self.message_storage = {}
        self.chat_messages = []
        self.recent_outgoing = deque(maxlen=MAX_RECENT_MESSAGES)
        self.animation_running = False
        self.pulse_color = "#ff3333"
        self._closing = False
        
        # UI Key Bindings
        self.bind("<Control-Return>", lambda e: self.send_msg(enforce_encryption=True))
        self.bind("<Control-l>", lambda e: self.clear_chat())
        self.bind("<Control-s>", lambda e: self.show_stats())
        self.bind("<Control-u>", lambda e: self.show_users())
        self.bind("<Control-f>", lambda e: self.search_entry.focus())
        self.bind("<Control-Shift-L>", lambda e: self.handle_logout())
        
        # Load configuration
        self.config = self.load_config()
        
        # Track which tabs have been built
        self.tabs_built = set()
        self._building_tab = False
        
        # Build UI
        self.is_authenticated = False
        self.auth_frame = None
        self.main_container = None
        self.build_ui()
        
        if not self.is_authenticated:
            self.show_auth_screen()
        
        # Log startup
        self.logger.log("APP_STARTED", "CipherCore application started")
        
        # Start status animation
        self.animate_status()
        
    def load_config(self):
        """Load application configuration"""
        default_config = {
            "theme": "dark",
            "last_port": str(DEFAULT_PORT),
            "auto_scroll": True,
            "show_timestamps": True
        }
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load config: {e}")
        return default_config
    
    def save_config(self):
        """Save application configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save config: {e}")
    

    def build_ui(self):
        """Build the user interface with premium aesthetics matching the reference image"""
        # Set overall window background
        self.configure(fg_color=BG_COLOR)
        
        # Main container that can be hidden
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True)
        
        if not self.is_authenticated:
            self.main_container.pack_forget()

        # --- HEADER ---
        header = ctk.CTkFrame(self.main_container, height=70, fg_color=BG_COLOR, corner_radius=0) # Reduced height
        header.pack(fill="x", padx=0, pady=0)
        header.pack_propagate(False)
        
        # Left side - Logo and Branding
        left_header = ctk.CTkFrame(header, fg_color="transparent")
        left_header.pack(side="left", fill="both", expand=True, padx=25, pady=5)
        
        # App logo
        try:
            png_path = resource_path("logo.png")
            if os.path.exists(png_path):
                img = Image.open(png_path)
                img_thumb = img.resize((54, 54), Image.Resampling.LANCZOS)
                self._header_icon = ctk.CTkImage(light_image=img_thumb, dark_image=img_thumb, size=(54, 54))
                ctk.CTkLabel(left_header, image=self._header_icon, text="").pack(side="left", padx=(0, 20), pady=5)
            else:
                ctk.CTkLabel(left_header, text="🔐", font=("Segoe UI", 36)).pack(side="left", padx=(0, 20))
        except Exception:
            pass
        
        # Brand container
        brand_frame = ctk.CTkFrame(left_header, fg_color="transparent")
        brand_frame.pack(side="left", fill="y", pady=10)
        
        ctk.CTkLabel(brand_frame, text="CipherCore", 
                    font=("Segoe UI", 34, "bold"), text_color=ACCENT_CYAN).pack(anchor="w", pady=(0, 0))
        
        # Right side - Global Actions
        right_header = ctk.CTkFrame(header, fg_color="transparent")
        right_header.pack(side="right", fill="y", padx=25, pady=15)
        
        self.theme_btn = ctk.CTkButton(right_header, text="🌙 Dark", width=100, height=35,
                                       command=self.toggle_theme, 
                                       fg_color="#1F2937", hover_color="#374151",
                                       font=("Segoe UI", 12), text_color=TEXT_COLOR)
        self.theme_btn.pack(side="left", padx=8)
        
        self.stats_header_btn = ctk.CTkButton(right_header, text="📊 Stats", width=100, height=35,
                                             command=self.show_stats,
                                             fg_color="#1F2937", hover_color="#374151",
                                             font=("Segoe UI", 12), text_color=TEXT_COLOR)
        self.stats_header_btn.pack(side="left", padx=8)
        
        self.logout_btn = ctk.CTkButton(right_header, text="🚪 Logout", width=100, height=35,
                                       command=self.handle_logout,
                                       fg_color="#374151", hover_color=DANGER_RED,
                                       font=("Segoe UI", 12, "bold"), text_color=TEXT_COLOR)
        self.logout_btn.pack(side="left", padx=8)
        
        # --- TAB NAVIGATION ---
        # Centered tab navigation bar
        tab_nav_container = ctk.CTkFrame(self.main_container, fg_color="transparent", height=45)
        tab_nav_container.pack(fill="x", pady=(5, 5))
        
        self.tabview = ctk.CTkTabview(self.main_container, fg_color="transparent", 
                                      bg_color="transparent",
                                      segmented_button_fg_color="#0F172A",
                                      segmented_button_selected_color=ACCENT_BLUE,
                                      segmented_button_selected_hover_color="#3B82F6",
                                      segmented_button_unselected_hover_color="#1E293B",
                                      corner_radius=12,
                                      command=self._on_tab_changed)
        # Added glow-like styling for active tab via border
        self.tabview._segmented_button.configure(font=("Segoe UI", 13, "bold"))
        # Note: Centering the segmented buttons in CTkTabview is tricky without internal modification.
        # We pack it normally, it stays at the top.
        self.tabview.pack(fill="both", expand=True, padx=10, pady=0)
        
        # Create tabs matching image
        self.tab_chat = self.tabview.add("💬 Chat")
        self.tab_encrypt = self.tabview.add("🔐 Encryption") 
        self.tab_file = self.tabview.add("📁 File Security")
        self.tab_tools = self.tabview.add("🛠️ Tools")
        
        # Build ONLY the first tab initially (Lazy Loading)
        self.build_chat_tab()
        self.tabs_built.add("Chat")
        
        # Hidden labels for status bar compatibility
        self.status_label = ctk.CTkLabel(self.main_container, text="")
        self.conn_status = ctk.CTkLabel(self.main_container, text="")
        self.conn_indicator = ctk.CTkLabel(self.main_container, text="")
        self.status_indicator = ctk.CTkLabel(self.main_container, text="")
        self.stats_label = ctk.CTkLabel(self.main_container, text="")

    def show_auth_screen(self):
        """Displays login/registration screen"""
        if self.auth_frame:
            self.auth_frame.destroy()
        
        self.auth_frame = ctk.CTkFrame(self, fg_color=BG_COLOR)
        self.auth_frame.pack(fill="both", expand=True)

        # Center content
        center_frame = ctk.CTkFrame(self.auth_frame, fg_color=CARD_BG, corner_radius=15, width=400, height=500)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        center_frame.pack_propagate(False)

        ctk.CTkLabel(center_frame, text="🔐 CipherCore", font=("Segoe UI", 32, "bold"), text_color=ACCENT_CYAN).pack(pady=(40, 5))
        ctk.CTkLabel(center_frame, text="Secure Authentication", font=("Segoe UI", 14), text_color=SUBTEXT_COLOR).pack(pady=(0, 30))

        # Username
        ctk.CTkLabel(center_frame, text="Username", font=("Segoe UI", 12), text_color=TEXT_COLOR).pack(anchor="w", padx=40)
        self.auth_user_entry = ctk.CTkEntry(center_frame, placeholder_text="Enter username", width=320, height=40, fg_color="#0D1117")
        self.auth_user_entry.pack(pady=(5, 15))

        # Password
        ctk.CTkLabel(center_frame, text="Password", font=("Segoe UI", 12), text_color=TEXT_COLOR).pack(anchor="w", padx=40)
        self.auth_pass_entry = ctk.CTkEntry(center_frame, placeholder_text="Enter password", show="*", width=320, height=40, fg_color="#0D1117")
        self.auth_pass_entry.pack(pady=(5, 25))

        # Buttons
        ctk.CTkButton(center_frame, text="Login", command=self.handle_login, width=320, height=45, fg_color=ACCENT_BLUE).pack(pady=5)
        ctk.CTkButton(center_frame, text="Register", command=self.handle_register, width=320, height=45, fg_color="transparent", border_width=1).pack(pady=5)

    def retry_mongo_connect(self):
        """Attempts to reconnect to MongoDB with detailed error feedback"""
        if self.mongo_manager:
            if self.mongo_manager.connect():
                self.mongo_status_label.configure(text="🟢 MongoDB Connected", text_color=SUCCESS_GREEN)
                if hasattr(self, 'retry_btn'):
                    self.retry_btn.destroy()
                messagebox.showinfo("Connected", "Successfully connected to MongoDB!")
            else:
                error_msg = getattr(self.mongo_manager, 'last_error', 'Unknown error')
                messagebox.showerror("Connection Failed", 
                                   f"Could not connect to MongoDB at {MONGO_URI}\n\n"
                                   f"Error: {error_msg}\n\n"
                                   "Common fixes:\n"
                                   "1. Open MongoDB Compass to start the service\n"
                                   "2. Ensure port 27017 is not blocked\n"
                                   "3. Check if your antivirus is blocking the connection")

    def handle_logout(self):
        """User logout: reset state and return to auth screen"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.is_authenticated = False
            self.current_user = None
            self.main_container.pack_forget()
            self.show_auth_screen()

    def handle_login(self):
        user = self.auth_user_entry.get()
        pwd = self.auth_pass_entry.get()
        if not self.mongo_manager:
            messagebox.showerror("Error", "MongoDB not connected")
            return
        
        success, msg, user_data = self.mongo_manager.login(user, pwd)
        if success:
            self.current_user = user_data
            self.on_auth_success()
        else:
            messagebox.showerror("Login Failed", msg)

    def handle_register(self):
        user = self.auth_user_entry.get()
        pwd = self.auth_pass_entry.get()
        if not self.mongo_manager:
            messagebox.showerror("Error", "MongoDB not connected")
            return
        
        success, msg = self.mongo_manager.register(user, pwd)
        if success:
            messagebox.showinfo("Success", "Account created successfully. You can now login.")
        else:
            messagebox.showerror("Registration Failed", msg)

    def on_auth_success(self):
        self.is_authenticated = True
        self.auth_frame.pack_forget()
        self.main_container.pack(fill="both", expand=True)

        # Pre-fill nickname in the server-chat row
        self.nickname_entry.delete(0, "end")
        self.nickname_entry.insert(0, self.current_user["username"])

        # ── Populate friends sidebar immediately on login ──────────────────
        self.refresh_friends_list()

        self.chat_add(f"Welcome back, {self.current_user['username']}! 👋", "success")

        # Start a periodic friends-list refresh (every 15 s) so newly
        # accepted requests appear automatically without restarting the app.
        self._poll_friends_list()

    def _poll_friends_list(self):
        """Refresh the friends sidebar every 15 seconds."""
        if self._closing:
            return
        if self.is_authenticated and self.current_user:
            self.refresh_friends_list()
        self.after(15000, self._poll_friends_list)


    def _build_tab_deferred(self, tab_name):
        """Build a specific tab in deferred manner"""
        if self._closing or self._building_tab or tab_name in self.tabs_built:
            return
        self._building_tab = True
        try:
            if tab_name == "Chat":
                self.build_chat_tab()
                self.tabs_built.add("Chat")
            elif tab_name == "Encryption":
                self.build_encrypt_tab()
                self.tabs_built.add("Encryption")
            elif tab_name == "File":
                self.build_file_tab()
                self.tabs_built.add("File")
            elif tab_name == "Tools":
                self.build_tools_tab()
                self.tabs_built.add("Tools")
        finally:
            self._building_tab = False
    
    def _on_tab_changed(self):
        """Handle tab change event for lazy loading"""  
        selected = self.tabview.get()
        
        # Map tab names to tab identifiers
        tab_mapping = {
            "💬 Chat": "Chat",
            "🔐 Encryption": "Encryption",
            "📁 File Security": "File",
            "🛠️ Tools": "Tools"
        }
        
        for tab_name, tab_id in tab_mapping.items():
            if tab_name in selected or selected in tab_name:
                if not self._closing:
                    self.after(50, self._build_tab_deferred, tab_id)
                break
    
    def toggle_theme(self):
        """Toggle between light and dark theme"""
        current = ctk.get_appearance_mode()
        new_theme = "light" if current == "Dark" else "dark"
        ctk.set_appearance_mode(new_theme)
        self.config["theme"] = new_theme
        self.save_config()
        # Update button icon
        self.theme_btn.configure(text="☀️" if new_theme == "light" else "🌙")
    
    def update_connection_status(self, connected=False, status_text=""):
        """Update header connection status indicator and tools bar button"""
        try:
            if connected:
                self.conn_indicator.configure(text_color="#00ff00")
                self.conn_status.configure(text=status_text or "Connected")
                if hasattr(self, 'connection_status_btn'):
                    self.connection_status_btn.configure(text="🟢 Online", text_color=SUCCESS_GREEN, fg_color="#0F172A")
            else:
                self.conn_indicator.configure(text_color="#ff3333")
                self.conn_status.configure(text=status_text or "Offline")
                if hasattr(self, 'connection_status_btn'):
                    self.connection_status_btn.configure(text="🔴 Offline", text_color=DANGER_RED, fg_color="#1E293B")
        except:
            pass
    
    def update_encryption_badge(self, enabled=False):
        """Update encryption status badge in header"""
        try:
            if enabled:
                self.enc_status.configure(text="🔒", text_color="#00d4ff")
            else:
                self.enc_status.configure(text="🔓", text_color="#999")
        except:
            pass
    
    def animate_status(self):
        """Animate the status indicator with pulsing effect"""
        if not self.animation_running:
            colors = ["#ff3333", "#ff6666", "#ff3333"]
            current_color = [0]
            
            def pulse():
                if not self._closing and self.animation_running and hasattr(self, 'status_indicator'):
                    try:
                        self.status_indicator.configure(text_color=colors[current_color[0]])
                        current_color[0] = (current_color[0] + 1) % len(colors)
                        self.after(600, pulse)
                    except:
                        pass
            
            self.animation_running = True
            pulse()
    
    def build_chat_tab(self):
        """Build the chat interface with sidebar for Global/Private/Server chat"""
        self.chat_mode = ctk.StringVar(value="server") # Default to existing server chat
        self.active_private_recipient = None
        
        # Main layout: Horizontal split
        self.chat_main_frame = ctk.CTkFrame(self.tab_chat, fg_color=BG_COLOR)
        self.chat_main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 1. Sidebar for Navigation (Global, Private, Server)
        sidebar = ctk.CTkFrame(self.chat_main_frame, width=200, fg_color="#10141B", corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        sidebar.pack(side="left", fill="y", padx=(0, 10))
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="💬 CHANNELS", font=("Segoe UI", 12, "bold"), text_color=ACCENT_CYAN).pack(pady=(20, 10), padx=20, anchor="w")
        
        # Navigation Buttons
        self.btn_global = ctk.CTkButton(sidebar, text="🌐 Global Chat", anchor="w", fg_color="transparent", 
                                       hover_color="#1F2937", command=lambda: self.switch_chat_mode("global"))
        self.btn_global.pack(fill="x", padx=10, pady=2)

        self.btn_server = ctk.CTkButton(sidebar, text="🖥️ Custom Server", anchor="w", fg_color="#1F2937", 
                                       hover_color="#1F2937", command=lambda: self.switch_chat_mode("server"))
        self.btn_server.pack(fill="x", padx=10, pady=2)

        # Search bar for friends
        self.friend_search_var = ctk.StringVar()
        self.friend_search_var.trace_add("write", lambda *args: self.refresh_friends_list())
        search_frame = ctk.CTkFrame(sidebar, fg_color="#0F172A", height=32, corner_radius=8)
        search_frame.pack(fill="x", padx=10, pady=(0, 10))
        search_frame.pack_propagate(False)
        ctk.CTkLabel(search_frame, text="🔍", font=("Segoe UI", 10)).pack(side="left", padx=(5, 2))
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search friends...", 
                                        fg_color="transparent", border_width=0, height=25,
                                        textvariable=self.friend_search_var, font=("Segoe UI", 11))
        self.search_entry.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(sidebar, text="👥 FRIENDS", font=("Segoe UI", 12, "bold"), text_color=ACCENT_CYAN).pack(pady=(10, 5), padx=20, anchor="w")
        
        # Scrollable area for friends
        self.friends_list = ctk.CTkScrollableFrame(sidebar, fg_color="transparent", height=300)
        self.friends_list.pack(fill="both", expand=True, padx=5)
        
        # Add Friend / Requests Buttons
        friend_actions = ctk.CTkFrame(sidebar, fg_color="transparent")
        friend_actions.pack(fill="x", padx=10, pady=(0,10))
        ctk.CTkButton(friend_actions, text="+ Add", font=("Segoe UI", 10), height=28,
                     fg_color="transparent", border_width=1,
                     command=self.show_add_friend_dialog).pack(side="left", fill="x", expand=True, padx=(0,4))
        self.requests_btn = ctk.CTkButton(friend_actions, text="🔔 Requests", font=("Segoe UI", 10), height=28,
                     fg_color="transparent", border_width=1, border_color=WARNING_ORANGE,
                     text_color=WARNING_ORANGE, command=self.show_friend_requests_dialog)
        self.requests_btn.pack(side="left", fill="x", expand=True, padx=(4,0))

        # 2. Main Chat Area
        chat_content = ctk.CTkFrame(self.chat_main_frame, fg_color="transparent")
        chat_content.pack(side="left", fill="both", expand=True)

        # --- MODE-SPECIFIC CONFIG AREA ---
        self.config_area = ctk.CTkFrame(chat_content, fg_color="#10141B", corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        self.config_area.pack(fill="x", pady=(0, 10))
        
        self.build_server_config_ui() # Initially show server config

        # --- CHAT TOOLS BAR ---
        tools_bar = ctk.CTkFrame(chat_content, fg_color="#10141B", corner_radius=8, height=45)
        tools_bar.pack(fill="x", pady=(0, 10))
        tools_bar.pack_propagate(False)
        
        inner_tools = ctk.CTkFrame(tools_bar, fg_color="transparent")
        inner_tools.pack(fill="y", padx=10)
        
        self.bubble_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(inner_tools, text="Bubbles", variable=self.bubble_var, 
                      command=self._toggle_bubble_mode, font=("Segoe UI", 10),
                      width=80, progress_color=ACCENT_BLUE).pack(side="right", padx=10)
        
        # Connection status indicator in tools bar
        self.connection_status_btn = ctk.CTkButton(inner_tools, text="🔴 Offline", width=100, height=28,
                                                 fg_color="#1E293B", text_color=DANGER_RED,
                                                 state="disabled", font=("Segoe UI", 10, "bold"))
        self.connection_status_btn.pack(side="right", padx=5)
        
        ctk.CTkButton(inner_tools, text="Clear", command=self.clear_chat, width=70, height=28,
                     fg_color="#34495e", hover_color="#2c3e50", font=("Segoe UI", 10)).pack(side="left", padx=5, pady=8)
        
        ctk.CTkButton(inner_tools, text="📊 Stats", command=self.show_stats, width=80, height=28,
                     fg_color="#8e44ad", hover_color="#7d3c98", font=("Segoe UI", 10)).pack(side="left", padx=5, pady=8)
        
        ctk.CTkButton(inner_tools, text="👥 Users", command=self.show_users, width=80, height=28,
                     fg_color="#2980b9", hover_color="#2471a3", font=("Segoe UI", 10)).pack(side="left", padx=5, pady=8)
        
        # --- CHAT DISPLAY CONTAINER (holds three separate boxes) ---
        self.chat_display_container = ctk.CTkFrame(chat_content, fg_color="transparent")
        self.chat_display_container.pack(fill="both", pady=(0, 10), expand=True)

        # ── Server box (socket chat) ──────────────────────────────────
        self.server_chat_box = ctk.CTkTextbox(
            self.chat_display_container, font=("Consolas", 11), wrap="word",
            fg_color="#000000", text_color="#ffffff",
            border_color="#3498DB", border_width=1, corner_radius=8,
            exportselection=False)
        self.server_chat_box.pack(fill="both", expand=True)

        # ── Global box (MongoDB global_chat) ─────────────────────────
        self.global_chat_box = ctk.CTkTextbox(
            self.chat_display_container, font=("Consolas", 11), wrap="word",
            fg_color="#000000", text_color="#ffffff",
            border_color=ACCENT_CYAN, border_width=1, corner_radius=8,
            exportselection=False)
        # hidden by default
        self.global_chat_box.pack_forget()

        # ── Private box (MongoDB private_chat) ────────────────────────
        self.private_chat_box = ctk.CTkTextbox(
            self.chat_display_container, font=("Consolas", 11), wrap="word",
            fg_color="#000000", text_color="#ffffff",
            border_color=SUCCESS_GREEN, border_width=1, corner_radius=8,
            exportselection=False)
        # hidden by default
        self.private_chat_box.pack_forget()

        # Backwards-compat alias so existing chat_add() still works
        self.chat_box = self.server_chat_box

        # --- INPUT AREA ---
        input_container = ctk.CTkFrame(chat_content, fg_color="transparent")
        input_container.pack(fill="x", pady=(0, 10))
        
        self.msg_entry = ctk.CTkEntry(input_container, placeholder_text="Type message...", 
                                     font=("Segoe UI", 12), height=45,
                                     fg_color="#0D1117", border_color=ACCENT_CYAN, border_width=1, corner_radius=10)
        self.msg_entry.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", lambda e: self.send_msg())
        self.msg_entry.bind("<KeyRelease>", lambda e: self._update_char_count())
        
        self.send_btn = ctk.CTkButton(input_container, text="🚀 SEND", command=self.send_msg, width=120, height=45,
                                     fg_color=GLOW_COLOR, text_color="#FFFFFF", 
                                     hover_color="#2563EB", font=("Segoe UI", 13, "bold"), corner_radius=10)
        self.send_btn.pack(side="left")

        # Encryption Toggle in Footer
        self.build_chat_footer(chat_content)
        
        # Load friends list initially
        self.refresh_friends_list()
        # Start background polling for MongoDB chats + friend requests
        self._poll_mongo_chats()
        self._poll_friend_requests()

    def _poll_mongo_chats(self):
        """Periodically refresh chat if in MongoDB mode."""
        if self._closing:
            return
        if self.is_authenticated and self.chat_mode.get() != "server":
            self.refresh_chat_display()
        self.after(3000, self._poll_mongo_chats)

    def _poll_friend_requests(self):
        """Show a badge on the Requests button if there are pending requests."""
        if self._closing:
            return
        if self.is_authenticated and self.mongo_manager and self.current_user:
            pending = self.mongo_manager.get_pending_requests(self.current_user["username"])
            if pending:
                self.requests_btn.configure(
                    text=f"🔔 Requests ({len(pending)})",
                    border_color=DANGER_RED, text_color=DANGER_RED)
            else:
                self.requests_btn.configure(
                    text="🔔 Requests",
                    border_color=WARNING_ORANGE, text_color=WARNING_ORANGE)
        self.after(5000, self._poll_friend_requests)

    def build_chat_footer(self, parent):
        """Build the encryption settings footer inside the chat area"""
        footer_frame = ctk.CTkFrame(parent, fg_color="#10141B", corner_radius=10)
        footer_frame.pack(fill="x", pady=(5, 0))
        
        footer_inner = ctk.CTkFrame(footer_frame, fg_color="transparent")
        footer_inner.pack(fill="x", padx=15, pady=8)
        
        # Grouped controls for better layout
        enc_group = ctk.CTkFrame(footer_inner, fg_color="transparent")
        enc_group.pack(side="left")

        ctk.CTkLabel(enc_group, text="📤 Encrypt:", font=("Segoe UI", 11, "bold"), text_color=ACCENT_CYAN).pack(side="left", padx=(0, 5))
        self.msg_enc_var = ctk.BooleanVar(value=False)
        enc_switch = ctk.CTkSwitch(enc_group, text="", variable=self.msg_enc_var,
                                  command=self.toggle_message_encryption, 
                                  width=45, progress_color=ACCENT_CYAN)
        enc_switch.pack(side="left", padx=(0, 15))

        dec_group = ctk.CTkFrame(footer_inner, fg_color="transparent")
        dec_group.pack(side="left", padx=10)

        ctk.CTkLabel(dec_group, text="📥 Decrypt:", font=("Segoe UI", 11, "bold"), text_color=SUCCESS_GREEN).pack(side="left", padx=(0, 5))
        self.msg_dec_var = ctk.BooleanVar(value=False)
        dec_switch = ctk.CTkSwitch(dec_group, text="", variable=self.msg_dec_var,
                                  command=self.toggle_message_decryption, 
                                  width=45, progress_color=SUCCESS_GREEN)
        dec_switch.pack(side="left", padx=(0, 15))
        
        pwd_group = ctk.CTkFrame(footer_inner, fg_color="transparent")
        pwd_group.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(pwd_group, text="🔑 Password:", font=("Segoe UI", 11), text_color="#D1D5DB").pack(side="left", padx=(10, 5))
        self.msg_enc_pwd = ctk.CTkEntry(pwd_group, placeholder_text="Enter key...", 
                                       show="*", height=28, font=("Segoe UI", 11),
                                       fg_color="#0D1117", border_color=BORDER_COLOR)
        self.msg_enc_pwd.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.msg_enc_pwd.bind("<KeyRelease>", self._on_msg_enc_pwd_change)
        
        ctk.CTkButton(footer_inner, text="🎲", command=self.generate_msg_encryption_pwd,
                     width=32, height=28, font=("Segoe UI", 12), fg_color=ACCENT_BLUE, hover_color="#2980b9").pack(side="left")

    def _on_decrypt_btn_click(self):
        """Helper to call decrypt on the currently visible chat box"""
        mode = self.chat_mode.get()
        if mode == "server":
            self._decrypt_selection(self.server_chat_box)
        elif mode == "global":
            self._decrypt_selection(self.global_chat_box)
        elif mode == "private":
            self._decrypt_selection(self.private_chat_box)

    def _decrypt_selection(self, textbox):
        """Decrypt the selected text in the chat box"""
        try:
            # Try to get selection from CTkTextbox or internal tk.Text
            try:
                selected_text = textbox.get("sel.start", "sel.end").strip()
            except tk.TclError:
                if hasattr(textbox, "_textbox"):
                    selected_text = textbox._textbox.get("sel.start", "sel.end").strip()
                else:
                    raise tk.TclError("No selection")
            
            if not selected_text:
                return
            
            # Robust extraction of Fernet tokens
            token_match = re.search(r'gAAAA[a-zA-Z0-9\-_=]{20,}', selected_text)
            cipher_text = token_match.group(0) if token_match else selected_text
            cipher_text = cipher_text.rstrip('.').strip()
            
            pwd = self.msg_enc_pwd.get().strip()
            if not pwd:
                pwd = simpledialog.askstring("Password", "Enter decryption password:", show='*', parent=self)
                if not pwd: return

            try:
                decrypted = decrypt_fernet(cipher_text, pwd)
                
                # Enhanced result dialog
                dialog = ctk.CTkToplevel(self)
                dialog.title("Decrypted Message")
                dialog.geometry("500x350")
                dialog.transient(self)
                dialog.configure(fg_color=BG_COLOR)
                
                header = ctk.CTkFrame(dialog, fg_color="#10141B", height=50)
                header.pack(fill="x")
                ctk.CTkLabel(header, text="🔓 DECRYPTED CONTENT", font=("Segoe UI", 14, "bold"), text_color=SUCCESS_GREEN).pack(pady=12)
                
                scroll_frame = ctk.CTkFrame(dialog, fg_color="transparent")
                scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)
                
                txt = ctk.CTkTextbox(scroll_frame, font=("Segoe UI", 12), fg_color="#000000", border_color=SUCCESS_GREEN, border_width=1)
                txt.pack(fill="both", expand=True)
                txt.insert("1.0", decrypted)
                txt.configure(state="disabled")
                
                footer = ctk.CTkFrame(dialog, fg_color="transparent")
                footer.pack(fill="x", pady=(0, 15))
                
                ctk.CTkButton(footer, text="📋 Copy Text", width=120, fg_color=ACCENT_BLUE, 
                             command=lambda: [self.clipboard_clear(), self.clipboard_append(decrypted), messagebox.showinfo("Copied", "Text copied to clipboard", parent=dialog)]).pack(side="left", padx=(20, 10))
                
                ctk.CTkButton(footer, text="Close", width=100, fg_color="#1F2937", command=dialog.destroy).pack(side="right", padx=20)
                
            except Exception:
                messagebox.showerror("Decryption Failed", "The content could not be decrypted.\n\nCheck your password and selection.", parent=self)
        except tk.TclError:
            messagebox.showinfo("No Selection", "Please select the encrypted text from the chat first.", parent=self)

    def switch_chat_mode(self, mode, recipient=None):
        """Switch between Server, Global, and Private chat modes with high-fidelity effects."""
        self.chat_mode.set(mode)
        self.active_private_recipient = recipient

        # Reset button styles and hide all boxes
        self.btn_global.configure(fg_color="transparent", border_width=0)
        self.btn_server.configure(fg_color="transparent", border_width=0)
        
        self.server_chat_box.pack_forget()
        self.global_chat_box.pack_forget()
        self.private_chat_box.pack_forget()

        active_box = None
        if mode == "server":
            self.btn_server.configure(fg_color="#1F2937", border_width=1, border_color=ACCENT_BLUE)
            self.server_chat_box.pack(fill="both", expand=True)
            self.chat_box = self.server_chat_box
            self.build_server_config_ui()
            active_box = self.server_chat_box

        elif mode == "global":
            self.btn_global.configure(fg_color="#1F2937", border_width=1, border_color=ACCENT_CYAN)
            self.global_chat_box.pack(fill="both", expand=True)
            self.chat_box = self.global_chat_box
            self._show_global_header()
            self.refresh_chat_display()
            active_box = self.global_chat_box

        elif mode == "private":
            self.private_chat_box.pack(fill="both", expand=True)
            self.chat_box = self.private_chat_box
            self._show_private_header(recipient)
            self.refresh_chat_display()
            active_box = self.private_chat_box

        # Apply Premium Gloss/Scanline Effect to active box
        if active_box:
            # Subtle glow border
            active_box.configure(border_width=2, border_color=GLOW_COLOR)
            # Faint scanline simulation via text spacing
            if hasattr(active_box, "_textbox"):
                active_box._textbox.configure(spacing1=2, spacing3=2, padx=10, pady=10)

    def _show_global_header(self):
        """Swap config_area content to the global-chat header."""
        for w in self.config_area.winfo_children():
            w.destroy()
        inner = ctk.CTkFrame(self.config_area, fg_color="transparent")
        inner.pack(fill="x", padx=15, pady=12)
        ctk.CTkLabel(inner, text="🌐 GLOBAL PUBLIC CHAT",
                    font=("Segoe UI", 14, "bold"), text_color=ACCENT_CYAN).pack(side="left")
        ctk.CTkLabel(inner, text="  •  visible to all users",
                    font=("Segoe UI", 10), text_color=SUBTEXT_COLOR).pack(side="left")

    def _show_private_header(self, friend_name):
        """Swap config_area content to the private-chat header."""
        for w in self.config_area.winfo_children():
            w.destroy()
        inner = ctk.CTkFrame(self.config_area, fg_color="transparent")
        inner.pack(fill="x", padx=15, pady=12)
        ctk.CTkLabel(inner, text=f"💬 PRIVATE CHAT",
                    font=("Segoe UI", 14, "bold"), text_color=SUCCESS_GREEN).pack(side="left")
        ctk.CTkLabel(inner, text=f"  with  {friend_name}",
                    font=("Segoe UI", 13), text_color=ACCENT_CYAN).pack(side="left", padx=(6,0))

    def refresh_friends_list(self):
        """Reload friends from MongoDB with search filtering and online status."""
        if not self.mongo_manager or not self.current_user:
            return
        
        search_query = self.friend_search_var.get().lower()
        
        for widget in self.friends_list.winfo_children():
            widget.destroy()
            
        friends = self.mongo_manager.get_friends(self.current_user["username"])
        if not friends:
            ctk.CTkLabel(self.friends_list, text="No friends yet",
                        font=("Segoe UI", 11), text_color=SUBTEXT_COLOR).pack(pady=20)
            return

        for f in friends:
            if search_query and search_query not in f.lower():
                continue
                
            row = ctk.CTkFrame(self.friends_list, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=5)
            
            # Simulated online status (could be integrated with real DB field later)
            is_online = random.choice([True, True, False]) # Simulation
            status_color = SUCCESS_GREEN if is_online else "#475569"
            
            # Status dot
            dot = ctk.CTkLabel(row, text="•", font=("Segoe UI", 24), text_color=status_color)
            dot.pack(side="left", padx=(5, 0))
            
            btn = ctk.CTkButton(row, text=f, anchor="w", fg_color="transparent",
                               font=("Segoe UI", 12), text_color=TEXT_COLOR,
                               hover_color="#1E293B", corner_radius=8, height=35,
                               command=lambda name=f: self.switch_chat_mode("private", name))
            btn.pack(side="left", fill="x", expand=True)
            
            # Subtle hover animation placeholder (handled by CTkButton)

    def show_add_friend_dialog(self):
        """Dialog to send a friend request by username."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Add Friend")
        dialog.geometry("360x200")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color=BG_COLOR)

        ctk.CTkLabel(dialog, text="Send Friend Request",
                    font=("Segoe UI", 16, "bold"), text_color=ACCENT_CYAN).pack(pady=(25, 5))
        ctk.CTkLabel(dialog, text="Enter the username you want to add:",
                    font=("Segoe UI", 11), text_color=SUBTEXT_COLOR).pack()

        entry = ctk.CTkEntry(dialog, placeholder_text="Username", width=280, height=38,
                            fg_color="#0D1117", border_color=ACCENT_CYAN)
        entry.pack(pady=12)
        entry.focus()

        def send():
            name = entry.get().strip()
            if not name:
                return
            ok, msg = self.mongo_manager.send_friend_request(
                self.current_user["username"], name)
            if ok:
                messagebox.showinfo("Sent", f"Friend request sent to {name}!", parent=dialog)
                dialog.destroy()
            else:
                messagebox.showerror("Error", msg, parent=dialog)

        entry.bind("<Return>", lambda e: send())
        ctk.CTkButton(dialog, text="Send Request", command=send,
                     width=280, height=38, fg_color=ACCENT_BLUE).pack()

    def show_friend_requests_dialog(self):
        """Show incoming pending friend requests with Accept/Decline buttons."""
        if not self.mongo_manager or not self.current_user:
            return
        pending = self.mongo_manager.get_pending_requests(self.current_user["username"])

        dialog = ctk.CTkToplevel(self)
        dialog.title("Friend Requests")
        dialog.geometry("400x480")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color=BG_COLOR)

        ctk.CTkLabel(dialog, text="🔔 Pending Friend Requests",
                    font=("Segoe UI", 16, "bold"), text_color=ACCENT_CYAN).pack(pady=(25, 10))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=10)

        if not pending:
            ctk.CTkLabel(scroll, text="No pending requests 🎉",
                        font=("Segoe UI", 13), text_color=SUBTEXT_COLOR).pack(pady=40)
        else:
            for requester in pending:
                card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=10)
                card.pack(fill="x", pady=6)
                inner = ctk.CTkFrame(card, fg_color="transparent")
                inner.pack(fill="x", padx=15, pady=10)
                ctk.CTkLabel(inner, text=f"👤 {requester}",
                            font=("Segoe UI", 13, "bold"), text_color=TEXT_COLOR).pack(side="left")
                btn_frame = ctk.CTkFrame(inner, fg_color="transparent")
                btn_frame.pack(side="right")

                def make_accept(r=requester):
                    self.mongo_manager.respond_friend_request(
                        self.current_user["username"], r, accept=True)
                    self.refresh_friends_list()
                    dialog.destroy()
                    self.show_friend_requests_dialog()
                    messagebox.showinfo("Accepted", f"You and {r} are now friends!")

                def make_decline(r=requester):
                    self.mongo_manager.respond_friend_request(
                        self.current_user["username"], r, accept=False)
                    dialog.destroy()
                    self.show_friend_requests_dialog()

                ctk.CTkButton(btn_frame, text="✅ Accept", width=80, height=28,
                             fg_color=SUCCESS_GREEN, text_color="#000",
                             command=make_accept).pack(side="left", padx=(0,6))
                ctk.CTkButton(btn_frame, text="❌ Decline", width=80, height=28,
                             fg_color=DANGER_RED, command=make_decline).pack(side="left")

        ctk.CTkButton(dialog, text="Close", command=dialog.destroy,
                     width=120, fg_color="#1F2937").pack(pady=10)

    def refresh_chat_display(self):
        """Load history from MongoDB into the ACTIVE mode's chat box with Bubble support."""
        if not self.mongo_manager or not self.mongo_manager.connected or not self.current_user:
            return

        mode = self.chat_mode.get()
        if mode == "server":
            self._refresh_chat_with_encryption_state()
            return

        history = []
        box = None

        if mode == "global":
            history = self.mongo_manager.get_global_messages(limit=80)
            box = self.global_chat_box
        elif mode == "private":
            if not self.active_private_recipient:
                return
            history = self.mongo_manager.get_private_messages(
                self.current_user["username"], self.active_private_recipient, limit=80)
            box = self.private_chat_box

        if not box: return
        box.configure(state="normal")
        box.delete("1.0", "end")
        
        pwd = self.msg_enc_pwd.get().strip() if hasattr(self, 'msg_enc_pwd') else ""
        
        for msg in history:
            ts      = msg["timestamp"].strftime("%H:%M:%S")
            sender  = msg.get("sender", "?")
            content = msg.get("content", "")
            is_me   = (sender == self.current_user["username"])
            
            display_content = content
            indicator = ""
            
            if content and self._looks_encrypted(content):
                if self.message_decryption_enabled and pwd:
                    try:
                        decrypted = decrypt_fernet(content, pwd)
                        display_content = decrypted
                        indicator = " 🔒"
                    except:
                        indicator = " 🔒"
                else:
                    indicator = " 🔒"
            
            label = "You" if is_me else sender
            
            if self.bubble_mode_enabled:
                # Bubble Mode
                tag_name = f"bubble_{id(msg)}"
                box.insert("end", f" {label} ", "username")
                box.insert("end", f" {ts}\n", "timestamp")
                box.insert("end", f" {display_content}{indicator} ", tag_name)
                box.insert("end", "\n\n")
                
                bg = GLOW_COLOR if is_me else "#1E293B"
                box.tag_config(tag_name, background=bg, foreground=TEXT_COLOR, lmargin1=20, lmargin2=20, rmargin=20, spacing1=5, spacing3=5)
            else:
                # Terminal Mode
                tag = "success" if is_me else "normal"
                box.insert("end", f"[{ts}] {label}: {display_content}{indicator}\n", tag)
            
        box.tag_config("success", foreground=SUCCESS_GREEN)
        box.tag_config("normal",  foreground=TEXT_COLOR)
        box.tag_config("username", foreground=ACCENT_CYAN, font=("Segoe UI", 10, "bold"))
        box.tag_config("timestamp", foreground=SUBTEXT_COLOR, font=("Segoe UI", 8))
        box.configure(state="disabled")
        box.see("end")
    
    def _looks_encrypted(self, content: str) -> bool:
        """Check if content looks like it's encrypted (base64 or Fernet format)"""
        if not content or len(content) < 20:
            return False
        try:
            # Fernet tokens are base64 and typically start with 'gAA' when decoded
            import base64
            base64.urlsafe_b64decode(content)
            return True
        except:
            return False

    def build_server_config_ui(self):
        """Standard server/client config UI."""
        for widget in self.config_area.winfo_children():
            widget.destroy()

        inner_config = ctk.CTkFrame(self.config_area, fg_color="transparent")
        inner_config.pack(fill="x", padx=15, pady=12)

        # Server Row
        srv_row = ctk.CTkFrame(inner_config, fg_color="transparent")
        srv_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(srv_row, text="🖥️ Server:",
                    font=("Segoe UI", 12, "bold"), text_color=ACCENT_CYAN).pack(side="left", padx=(0, 10))
        self.server_btn = ctk.CTkButton(srv_row, text="▶ Start", command=self.toggle_server,
                                       fg_color=SUCCESS_GREEN, width=80, height=30)
        self.server_btn.pack(side="left", padx=10)
        self.server_pwd_entry = ctk.CTkEntry(srv_row, placeholder_text="server password (optional)",
                                            width=180, height=30, show="*")
        self.server_pwd_entry.pack(side="left")

        # Client Row
        cli_row = ctk.CTkFrame(inner_config, fg_color="transparent")
        cli_row.pack(fill="x")
        ctk.CTkLabel(cli_row, text="👤 Nick:", font=("Segoe UI", 11)).pack(side="left")
        self.nickname_entry = ctk.CTkEntry(cli_row, width=100, height=30)
        if hasattr(self, "current_user") and self.current_user:
            self.nickname_entry.insert(0, self.current_user["username"])
        self.nickname_entry.pack(side="left", padx=5)

        ctk.CTkLabel(cli_row, text="Host:", font=("Segoe UI", 11)).pack(side="left")
        self.host_entry = ctk.CTkEntry(cli_row, width=110, height=30)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side="left", padx=5)

        self.client_pwd_entry = ctk.CTkEntry(cli_row, placeholder_text="passwd",
                                            width=90, height=30, show="*")
        self.client_pwd_entry.pack(side="left", padx=5)

        self.connect_btn = ctk.CTkButton(cli_row, text="🔌 Connect",
                                        command=self.connect_server,
                                        fg_color=ACCENT_BLUE, width=100, height=30)
        self.connect_btn.pack(side="left", padx=5)

    def build_encrypt_tab(self):
        """Build the encryption interface with modern styling"""
        frame = ctk.CTkFrame(self.tab_encrypt, fg_color=BG_COLOR)
        frame.pack(fill="both", expand=True, padx=25, pady=20)

        ctk.CTkLabel(frame, text="🔒 Text Encryption & Decryption", 
                    font=("Segoe UI", 24, "bold"), text_color=ACCENT_CYAN).pack(anchor="w", pady=(0, 20))

        # Input Area
        ctk.CTkLabel(frame, text="📥 Input Text", font=("Segoe UI", 14, "bold"), text_color=TEXT_COLOR).pack(anchor="w", pady=(0, 5))
        self.input_text = ctk.CTkTextbox(frame, height=180, font=("Consolas", 12),
                                        fg_color="#000000", border_color=BORDER_COLOR, border_width=1)
        self.input_text.pack(fill="x", pady=(0, 20))

        # Controls Container
        controls = ctk.CTkFrame(frame, fg_color="#10141B", corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        controls.pack(fill="x", pady=(0, 20))

        inner_ctrl = ctk.CTkFrame(controls, fg_color="transparent")
        inner_ctrl.pack(fill="x", padx=20, pady=15)

        # Left Column: Algorithm and Password
        left_col = ctk.CTkFrame(inner_ctrl, fg_color="transparent")
        left_col.pack(side="left", fill="both", expand=True)

        # Row 1: Algorithm
        alg_row = ctk.CTkFrame(left_col, fg_color="transparent")
        alg_row.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(alg_row, text="Algorithm:", font=("Segoe UI", 12), text_color=SUBTEXT_COLOR).pack(side="left", padx=(0, 10))
        self.cipher_choice = ctk.CTkOptionMenu(alg_row, values=["Fernet", "AES-256", "ChaCha20", "Triple DES", "AES-CTR"], 
                                              width=160, font=("Segoe UI", 11),
                                              fg_color="#1F2937", button_color=ACCENT_BLUE, 
                                              button_hover_color="#2980b9", text_color="#ffffff")
        self.cipher_choice.set("Fernet")
        self.cipher_choice.pack(side="left")

        # Row 2: Password
        pwd_row = ctk.CTkFrame(left_col, fg_color="transparent")
        pwd_row.pack(fill="x")
        ctk.CTkLabel(pwd_row, text="Password:", font=("Segoe UI", 12), text_color=SUBTEXT_COLOR).pack(side="left", padx=(0, 10))
        self.password_entry = ctk.CTkEntry(pwd_row, placeholder_text="Enter encryption password", 
                                          show="*", width=250, height=35, font=("Segoe UI", 11),
                                          fg_color="#0D1117", border_color=BORDER_COLOR)
        self.password_entry.pack(side="left", padx=(0, 10))
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)
        
        ctk.CTkButton(pwd_row, text="🎲 Gen", command=self.generate_password, 
                     width=80, height=35, font=("Segoe UI", 11), 
                     fg_color="#34495e", hover_color="#2c3e50").pack(side="left")

        # Right Column: Strength Meter
        right_col = ctk.CTkFrame(inner_ctrl, fg_color="transparent")
        right_col.pack(side="right", padx=(20, 0))
        
        ctk.CTkLabel(right_col, text="Strength:", font=("Segoe UI", 12), text_color=SUBTEXT_COLOR).pack(anchor="w")
        self.strength_bar = ctk.CTkProgressBar(right_col, width=150, height=10, progress_color=DANGER_RED)
        self.strength_bar.pack(pady=5)
        self.strength_bar.set(0)
        self.strength_label = ctk.CTkLabel(right_col, text="No Password", font=("Segoe UI", 11), text_color=DANGER_RED)
        self.strength_label.pack(anchor="e")

        # Action Buttons
        btns_row = ctk.CTkFrame(frame, fg_color="transparent")
        btns_row.pack(pady=(0, 20))
        
        ctk.CTkButton(btns_row, text="🔒 Encrypt", command=self.encrypt_text, width=130, height=40,
                     fg_color=SUCCESS_GREEN, hover_color="#27ae60", font=("Segoe UI", 13, "bold"), text_color="#000000").pack(side="left", padx=10)
        
        ctk.CTkButton(btns_row, text="🔓 Decrypt", command=self.decrypt_text, width=130, height=40,
                     fg_color=WARNING_ORANGE, hover_color="#d35400", font=("Segoe UI", 13, "bold"), text_color="#000000").pack(side="left", padx=10)
        
        ctk.CTkButton(btns_row, text="📋 Copy", command=self.copy_output, width=100, height=40,
                     fg_color=ACCENT_BLUE, hover_color="#2980b9", font=("Segoe UI", 12)).pack(side="left", padx=10)
        
        ctk.CTkButton(btns_row, text="🔄 Swap", command=self.swap_texts, width=100, height=40,
                     fg_color="#1F2937", font=("Segoe UI", 12)).pack(side="left", padx=10)

        # Output area
        ctk.CTkLabel(frame, text="📤 Output Text", font=("Segoe UI", 14, "bold"), text_color=TEXT_COLOR).pack(anchor="w", pady=(0, 5))
        self.output_text = ctk.CTkTextbox(frame, height=180, font=("Consolas", 12),
                                         fg_color="#000000", border_color=BORDER_COLOR, border_width=1)
        self.output_text.pack(fill="x")

    def build_file_tab(self):
        """Build the file encryption interface with modern styling"""
        frame = ctk.CTkFrame(self.tab_file, fg_color=BG_COLOR)
        frame.pack(fill="both", expand=True, padx=25, pady=20)

        ctk.CTkLabel(frame, text="📁 File Encryption & Security", 
                    font=("Segoe UI", 24, "bold"), text_color=ACCENT_CYAN).pack(anchor="w", pady=(0, 20))

        # Password Section
        pwd_section = ctk.CTkFrame(frame, fg_color="#10141B", corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        pwd_section.pack(fill="x", pady=(0, 25))
        
        inner_pwd = ctk.CTkFrame(pwd_section, fg_color="transparent")
        inner_pwd.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(inner_pwd, text="🔑 File Password:", font=("Segoe UI", 13, "bold"), text_color=TEXT_COLOR).pack(side="left", padx=(0, 15))
        self.file_pwd_entry = ctk.CTkEntry(inner_pwd, show="*", placeholder_text="Enter secure password for file...", 
                                          width=350, height=40, font=("Segoe UI", 12),
                                          fg_color="#0D1117", border_color=ACCENT_CYAN)
        self.file_pwd_entry.pack(side="left", padx=(0, 15))
        
        ctk.CTkButton(inner_pwd, text="🎲 Generate", command=self.generate_file_password, 
                     width=100, height=40, font=("Segoe UI", 11),
                     fg_color="#34495e", hover_color="#2c3e50").pack(side="left")

        # Operations container
        ops_frame = ctk.CTkFrame(frame, fg_color="transparent")
        ops_frame.pack(fill="both", expand=True)
        
        # Left: Encryption card
        enc_card = ctk.CTkFrame(ops_frame, fg_color="#10141B", corner_radius=15, border_width=1, border_color=SUCCESS_GREEN)
        enc_card.pack(side="left", fill="both", expand=True, padx=(0, 12))
        
        ctk.CTkLabel(enc_card, text="🔒 Protect File", font=("Segoe UI", 16, "bold"), text_color=SUCCESS_GREEN).pack(pady=(20, 10))
        ctk.CTkLabel(enc_card, text="Standard encryption for all file types", font=("Segoe UI", 11), text_color=SUBTEXT_COLOR).pack(pady=(0, 20))
        
        ctk.CTkButton(enc_card, text="Select & Encrypt", command=self.encrypt_file, width=180, height=45,
                     fg_color=SUCCESS_GREEN, hover_color="#27ae60", font=("Segoe UI", 13, "bold"), text_color="#000000").pack(pady=20)

        # Right: Decryption card
        dec_card = ctk.CTkFrame(ops_frame, fg_color="#10141B", corner_radius=15, border_width=1, border_color=WARNING_ORANGE)
        dec_card.pack(side="left", fill="both", expand=True, padx=(12, 0))
        
        ctk.CTkLabel(dec_card, text="🔓 Restore File", font=("Segoe UI", 16, "bold"), text_color=WARNING_ORANGE).pack(pady=(20, 10))
        ctk.CTkLabel(dec_card, text="Decrypt files back to original format", font=("Segoe UI", 11), text_color=SUBTEXT_COLOR).pack(pady=(0, 20))
        
        ctk.CTkButton(dec_card, text="Select & Decrypt", command=self.decrypt_file, width=180, height=45,
                     fg_color=WARNING_ORANGE, hover_color="#d35400", font=("Segoe UI", 13, "bold"), text_color="#000000").pack(pady=20)
        
        # Info at bottom
        info_frame = ctk.CTkFrame(frame, fg_color="#10141B", corner_radius=10)
        info_frame.pack(pady=15, padx=0, fill="x")
        
        info_text = """ℹ️ File Encryption Information:
• Uses military-grade AES-256 encryption with Fernet
• Encrypted files get .encrypted extension
• Keep your password safe - cannot be recovered!
• Supports all file types and sizes
• Fast and secure encryption algorithm"""

        ctk.CTkLabel(info_frame, text=info_text, font=("Segoe UI", 11), 
                    justify="left", text_color=SUBTEXT_COLOR).pack(padx=15, pady=12)


    def build_tools_tab(self):
        """Build the tools interface with modern grid layout"""
        frame = ctk.CTkFrame(self.tab_tools, fg_color=BG_COLOR)
        frame.pack(fill="both", expand=True, padx=25, pady=20)

        ctk.CTkLabel(frame, text="🛠️ Security & Utility Tools", 
                    font=("Segoe UI", 24, "bold"), text_color=ACCENT_CYAN).pack(anchor="w", pady=(0, 20))

        # Main scrollable container for tools
        container = ctk.CTkScrollableFrame(frame, fg_color="transparent", label_text="")
        container.pack(fill="both", expand=True)

        # Left column
        left_col = ctk.CTkFrame(container, fg_color="transparent")
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Right column
        right_col = ctk.CTkFrame(container, fg_color="transparent")
        right_col.pack(side="left", fill="both", expand=True, padx=(10, 0))

        # Tool 1: Password Generator
        self.create_tool_card(left_col, "🎲 Password Generator", 
                            "Generate cryptographically secure passwords",
                            self.tool_password_gen)

        # Tool 2: Hash Calculator
        self.create_tool_card(right_col, "🔢 Hash Calculator",
                            "Calculate SHA-256, MD5, and other hashes",
                            self.tool_hash_calc)

        # Tool 3: Base64 Tool
        self.create_tool_card(left_col, "⚙️ Base64 Tool",
                            "Encode and decode Base64 strings",
                            self.tool_base64)

        # Tool 4: QR Code Generator
        self.create_tool_card(right_col, "📱 QR Code Generator",
                            "Generate QR codes from text or URLs",
                            self.tool_qr_generator)

        # Tool 5: Text Analyzer
        self.create_tool_card(left_col, "📊 Text Analyzer",
                            "Analyze text statistics and character count",
                            self.tool_text_analyzer)

        # Tool 6: UUID Generator
        self.create_tool_card(right_col, "🆔 UUID Generator",
                            "Generate unique identifiers (UUIDs)",
                            self.tool_uuid_generator)

        # Tool 7: Color Picker
        self.create_tool_card(left_col, "🎨 Color Picker",
                            "Pick colors and get hex/RGB codes",
                            self.tool_color_picker)

        # Tool 8: Checksum Calculator
        self.create_tool_card(right_col, "✅ File Checksum",
                            "Calculate file checksums for integrity",
                            self.tool_checksum)

    def create_tool_card(self, parent, title, description, command):
        """Create a tool card with premium styling"""
        card = ctk.CTkFrame(parent, fg_color="#10141B", corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        card.pack(pady=10, padx=5, fill="x")
        
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", padx=20, pady=18)
        
        ctk.CTkLabel(inner, text=title, font=("Segoe UI", 14, "bold"), text_color=ACCENT_CYAN).pack(anchor="w")
        ctk.CTkLabel(inner, text=description, font=("Segoe UI", 11), 
                    text_color=SUBTEXT_COLOR).pack(pady=(5, 15), anchor="w")
        
        ctk.CTkButton(inner, text="Launch Tool", command=command,
                     fg_color=ACCENT_BLUE, hover_color="#2980b9", height=32,
                     font=("Segoe UI", 11, "bold")).pack(fill="x")

    # ========== LOGS & ABOUT TABS ==========

    
    # ========== CHAT METHODS ==========
        
    # ========== CHAT METHODS ==========
    def _toggle_bubble_mode(self):
        """Toggle between terminal and bubble chat view"""
        self.bubble_mode_enabled = self.bubble_var.get()
        self._refresh_chat_with_encryption_state()

    def chat_add(self, message, msg_type="message", target_box=None, encrypted_content=""):
        """Add message with support for Bubbles and Username Highlighting"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        display_message = message
        indicator = ""
        pwd = self.msg_enc_pwd.get().strip() if hasattr(self, 'msg_enc_pwd') else ""
        
        if encrypted_content:
            if self.message_decryption_enabled and pwd:
                try:
                    raw_content = encrypted_content
                    if ": " in encrypted_content:
                        raw_content = encrypted_content.split(": ", 1)[1]
                    display_message = decrypt_fernet(raw_content, pwd)
                    if ": " in encrypted_content:
                        display_message = f"{encrypted_content.split(': ', 1)[0]}: {display_message}"
                    indicator = " 🔒"
                except:
                    indicator = " 🔒"
                    display_message = encrypted_content
            else:
                indicator = " 🔒"
                display_message = encrypted_content
        
        msg_obj = {'timestamp': timestamp, 'content': message, 'type': msg_type, 'encrypted_content': encrypted_content}
        if self.chat_messages and isinstance(self.chat_messages[-1], dict):
            if self.chat_messages[-1]['content'] == message and self.chat_messages[-1]['type'] == msg_type:
                return
        self.chat_messages.append(msg_obj)
        
        if self._closing: return
        box = target_box if target_box is not None else (self.chat_box if hasattr(self, 'chat_box') else self.server_chat_box)
            
        try:
            box.configure(state="normal")
            
            # Modern Bubble Mode or Terminal Mode
            if self.bubble_mode_enabled and msg_type == "message" and ": " in display_message:
                user, text = display_message.split(": ", 1)
                is_me = user.startswith("You")
                
                # Bubble Layout simulation using tags
                tag_name = f"bubble_{len(self.chat_messages)}"
                box.insert("end", f" {user} ", "username")
                box.insert("end", f" {timestamp}\n", "timestamp")
                box.insert("end", f" {text}{indicator} ", tag_name)
                box.insert("end", "\n\n")
                
                # Configure bubble tag
                bg = "#1E293B" if not is_me else GLOW_COLOR
                fg = TEXT_COLOR
                box.tag_config(tag_name, background=bg, foreground=fg, lmargin1=20, lmargin2=20, rmargin=20, spacing1=5, spacing3=5)
                box.tag_config("username", foreground=ACCENT_CYAN, font=("Segoe UI", 10, "bold"))
                box.tag_config("timestamp", foreground=SUBTEXT_COLOR, font=("Segoe UI", 8))
            else:
                # Terminal Mode
                if msg_type == "system": formatted = f"[{timestamp}] 🔹 {display_message}"
                elif msg_type == "error": formatted = f"[{timestamp}] ❌ {display_message}"
                elif msg_type == "success": formatted = f"[{timestamp}] ✅ {display_message}{indicator}"
                elif msg_type == "warning": formatted = f"[{timestamp}] ⚠️ {display_message}"
                else: formatted = f"[{timestamp}] {display_message}{indicator}"
                
                box.insert("end", formatted + "\n", msg_type if msg_type in ["system","error","success","warning"] else "normal")
            
            box.configure(state="disabled")
            box.see("end")
            
            # Global tag configs
            box.tag_config("system", foreground=ACCENT_BLUE)
            box.tag_config("error",  foreground=DANGER_RED)
            box.tag_config("success", foreground=SUCCESS_GREEN)
            box.tag_config("warning", foreground=WARNING_ORANGE)
            box.tag_config("normal",  foreground=TEXT_COLOR)
        except Exception as e:
            print(f"Chat error: {e}")
        
        # Log to system logger
        if msg_type == "message":
            self.logger.log("CHAT_MESSAGE", message)
        else:
            self.logger.log(f"CHAT_{msg_type.upper()}", message)
        
    def send_msg(self, enforce_encryption=False):
        """Send message to the correct backend based on the active chat mode."""
        message = self.msg_entry.get().strip()
        if not message:
            return

        mode = self.chat_mode.get()
        is_encrypted_send = self.message_encryption_enabled or enforce_encryption
        content_to_send = message
        encrypted_content = ""
        pwd = ""

        # --- 1. PREPARE ENCRYPTED CONTENT IF NEEDED ---
        if is_encrypted_send:
            pwd = self.msg_enc_pwd.get().strip()
            if not pwd:
                messagebox.showwarning("Password Required", "Enter encryption password", parent=self)
                return
            try:
                encrypted_content = encrypt_fernet(message, pwd)
                content_to_send = encrypted_content
            except Exception as e:
                messagebox.showerror("Encryption Error", str(e), parent=self)
                return

        # --- 2. SEND TO TARGET BACKEND ---
        if mode == "server":
            if self.client:
                try:
                    self.client.send_message(content_to_send)
                    # For local display
                    if is_encrypted_send:
                        self.chat_add(f"You ({self.client.nickname}): {message}", "success", encrypted_content=encrypted_content)
                    else:
                        self.chat_add(f"You ({self.client.nickname}): {message}", "success")
                    
                    self.msg_entry.delete(0, "end")
                    # Optional: Persist to DB if connected
                    if self.mongo_manager and self.mongo_manager.connected:
                        srv_id = getattr(self, "_server_id", "local")
                        self.mongo_manager.save_server_message(
                            server_id=srv_id, channel="#general",
                            sender=self.client.nickname, content=content_to_send)
                except Exception as e:
                    self.chat_add(f"❌ Send failed: {str(e)}", "error")
            else:
                self.chat_add("❌ Not connected to a server", "error")
            return

        # --- 3. MONGODB MODES (Global/Private) ---
        if not self.mongo_manager or not self.mongo_manager.connected:
            self.chat_add("❌ Database disconnected", "error")
            return
        if not self.current_user:
            self.chat_add("❌ Authentication required", "error")
            return

        sender = self.current_user["username"]
        ok = False

        if mode == "global":
            ok = self.mongo_manager.save_global_message(sender=sender, content=content_to_send)
        elif mode == "private":
            if not self.active_private_recipient:
                self.chat_add("❌ Select a recipient first", "error")
                return
            ok = self.mongo_manager.save_private_message(
                sender=sender, recipient=self.active_private_recipient, content=content_to_send)

        if ok:
            self.msg_entry.delete(0, "end")
            self.refresh_chat_display()
            self.mongo_manager.save_log(f"{sender} sent {mode} message", "INFO", "chat", sender)
        else:
            self.chat_add("❌ Message failed to send", "error")
            self.chat_add("❌ Failed to send message", "error", target_box=self.chat_box)

    def toggle_message_encryption(self):
        """Toggle outgoing message encryption"""
        self.message_encryption_enabled = self.msg_enc_var.get()
        if self.message_encryption_enabled:
            pwd = self.msg_enc_pwd.get().strip()
            if not pwd:
                messagebox.showwarning("Password Required", "Please enter an encryption password to send secure messages")
                self.msg_enc_var.set(False)
                self.message_encryption_enabled = False
                return
            self.message_encryption_password = pwd
            self.update_encryption_badge(True)
            self.chat_add("🔒 Outgoing Encryption Enabled (New messages will be sent as ciphertext)", "success")
        else:
            self.update_encryption_badge(False)
            self.chat_add("🔓 Outgoing Encryption Disabled (Messages will be sent as plaintext)", "system")

    def toggle_message_decryption(self):
        """Toggle incoming message decryption view"""
        self.message_decryption_enabled = self.msg_dec_var.get()
        self._refresh_chat_with_encryption_state()
        if self.message_decryption_enabled:
            self.chat_add("🛡️ Decryption Mode Active (Past messages will be decrypted if password matches)", "success")
        else:
            self.chat_add("♻️ Decryption Mode Disabled (Encrypted messages shown as raw ciphertext)", "system")
    
    def generate_msg_encryption_pwd(self):
        """Generate random password for message encryption"""
        pwd = generate_random_password(12)
        self.msg_enc_pwd.delete(0, "end")
        self.msg_enc_pwd.insert(0, pwd)
        self._on_msg_enc_pwd_change()
        
    def _on_msg_enc_pwd_change(self, event=None):
        """Triggered when encryption password entry is modified - updates UI live"""
        if self.message_decryption_enabled:
            self._refresh_chat_with_encryption_state()
    
    def _refresh_chat_with_encryption_state(self):
        """Full re-rendering of the server chat box with Bubble/Terminal support."""
        try:
            box = self.server_chat_box
            box.configure(state="normal")
            box.delete("1.0", "end")
            
            pwd = self.msg_enc_pwd.get().strip()
            
            for msg_obj in self.chat_messages:
                if not isinstance(msg_obj, dict): continue
                
                ts = msg_obj.get('timestamp', '??:??:??')
                content = msg_obj.get('content', '')
                msg_type = msg_obj.get('type', 'message')
                enc_content = msg_obj.get('encrypted_content', '')
                
                display_msg = content
                indicator = ""
                
                if enc_content:
                    if self.message_decryption_enabled and pwd:
                        try:
                            raw = enc_content
                            if ": " in enc_content:
                                raw = enc_content.split(": ", 1)[1]
                            decrypted = decrypt_fernet(raw, pwd)
                            if ": " in enc_content:
                                display_msg = f"{enc_content.split(': ', 1)[0]}: {decrypted}"
                            else:
                                display_msg = decrypted
                            indicator = " 🔒"
                        except:
                            display_msg = enc_content
                            indicator = " 🔒"
                    else:
                        display_msg = enc_content
                        indicator = " 🔒"
                
                # Bubble Mode Logic
                if self.bubble_mode_enabled and msg_type == "message" and ": " in display_msg:
                    user, text = display_msg.split(": ", 1)
                    is_me = user.startswith("You")
                    tag_name = f"bubble_srv_{id(msg_obj)}"
                    
                    box.insert("end", f" {user} ", "username")
                    box.insert("end", f" {ts}\n", "timestamp")
                    box.insert("end", f" {text}{indicator} ", tag_name)
                    box.insert("end", "\n\n")
                    
                    bg = GLOW_COLOR if is_me else "#1E293B"
                    box.tag_config(tag_name, background=bg, foreground=TEXT_COLOR, lmargin1=20, lmargin2=20, rmargin=20, spacing1=5, spacing3=5)
                else:
                    # Terminal Mode
                    if msg_type == "system": formatted = f"[{ts}] 🔹 {display_msg}"
                    elif msg_type == "error": formatted = f"[{ts}] ❌ {display_msg}"
                    elif msg_type == "success": formatted = f"[{ts}] ✅ {display_msg}{indicator}"
                    elif msg_type == "warning": formatted = f"[{ts}] ⚠️ {display_msg}"
                    else: formatted = f"[{ts}] {display_msg}{indicator}"
                    box.insert("end", formatted + "\n", msg_type if msg_type in ["system","error","success","warning"] else "normal")
            
            box.tag_config("system", foreground=ACCENT_BLUE)
            box.tag_config("error",  foreground=DANGER_RED)
            box.tag_config("success", foreground=SUCCESS_GREEN)
            box.tag_config("warning", foreground=WARNING_ORANGE)
            box.tag_config("normal",  foreground=TEXT_COLOR)
            box.tag_config("username", foreground=ACCENT_CYAN, font=("Segoe UI", 10, "bold"))
            box.tag_config("timestamp", foreground=SUBTEXT_COLOR, font=("Segoe UI", 8))
            box.configure(state="disabled")
            box.see("end")
        except Exception as e:
            print(f"Refresh error: {e}")
            
    def clear_chat(self):
        """Clear only the currently visible chat box."""
        if messagebox.askyesno("Clear Chat", "Clear messages in this view?"):
            mode = self.chat_mode.get()
            box = {
                "server":  self.server_chat_box,
                "global":  self.global_chat_box,
                "private": self.private_chat_box,
            }.get(mode, self.server_chat_box)
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.configure(state="disabled")
            if mode == "server":
                self.chat_messages.clear()

    def toggle_server(self):
        """Toggle server on/off"""
        if self.server and self.server.running:
            self.stop_server()
        else:
            self.start_server()
    
    def generate_server_password(self):
        """Generate random secure password for server"""
        password = generate_random_password(12)
        self.server_pwd_entry.delete(0, "end")
        self.server_pwd_entry.insert(0, password)
            
    def start_server(self):
        """Start the chat server"""
        try:
            server_pwd = self.server_pwd_entry.get().strip()
            # Password is optional - if empty, server runs without password
            
            port = DEFAULT_PORT
            self.server = ChatServer(self, port, server_pwd)
            if self.server.start():
                self.server_btn.configure(text="⏹ Stop", fg_color=DANGER_RED)
                self.update_connection_status(True, "🟢 Server Active")
                if server_pwd:
                    self.chat_add(f"🖥️ Server started on port {port} with password protection", "system")
                else:
                    self.chat_add(f"⚠️ Server started on port {port} (WARNING: No password set!)", "warning")
                return True
        except Exception as e:
            self.chat_add(f"❌ Failed to start server: {str(e)}", "error")
        return False
            
    def stop_server(self):
        """Stop the chat server, guarding against already-destroyed widgets."""
        if self.server:
            # Disconnect all clients first
            for client_sock in list(self.server.clients.keys()):
                try:
                    client_sock.close()
                except Exception:
                    pass
            self.server.stop()
            # The server_btn may already be destroyed if we are closing the app
            try:
                self.server_btn.configure(text="▶ Start", fg_color=SUCCESS_GREEN)
            except Exception:
                pass
            try:
                self.update_connection_status(False, "🔴 Offline")
            except Exception:
                pass
            if not self._closing:
                self.chat_add("🖥️ Server stopped", "system")

    def connect_server(self):
        """Connect to a chat server"""
        nick = self.nickname_entry.get().strip()
        pwd = self.client_pwd_entry.get().strip()
        host = self.host_entry.get().strip() or "127.0.0.1"
        
        if not nick:
            messagebox.showwarning("Nickname Required", 
                                 "Please enter a nickname to connect")
            return
        
        try:
            self.disconnect()
            self.chat_add(f"🔄 Connecting to {host}:{DEFAULT_PORT}...", "system")
            self.client = ChatClient(self, host, DEFAULT_PORT, nick, pwd)
            if self.client.running:
                self.update_connection_status(True, f"🟢 {nick}")
                self.chat_add(f"✅ Connected as {nick}", "success")
            
        except Exception as e:
            self.chat_add(f"❌ Connection failed: {str(e)}", "error")
            self.logger.log("CONNECTION_ERROR", f"Failed to connect: {e}")
    
    def disconnect(self):
        """Disconnect from server"""
        if self.client:
            self.client.disconnect()
            self.client = None
        self.update_connection_status(False, "🔴 Offline")
        
    def show_stats(self):
        """Show chat statistics"""
        stats_window = ctk.CTkToplevel(self)
        stats_window.title("📊 Chat Statistics")
        stats_window.geometry("400x350")
        stats_window.transient(self)
        
        ctk.CTkLabel(stats_window, text="📊 Chat Statistics", 
                    font=("Arial", 18, "bold")).pack(pady=20)
        
        total_msgs = len(self.chat_messages)
        system_msgs = 0
        for m in self.chat_messages:
            if isinstance(m, dict):
                if m.get('type') in ['system', 'error', 'warning']:
                    system_msgs += 1
            elif isinstance(m, str):
                if any(icon in m for icon in ["🔹", "❌", "⚠️"]):
                    system_msgs += 1
        user_msgs = total_msgs - system_msgs
        
        stats_frame = ctk.CTkFrame(stats_window)
        stats_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(stats_frame, text=f"Total Messages: {total_msgs}", 
                    font=("Arial", 14)).pack(pady=10)
        ctk.CTkLabel(stats_frame, text=f"User Messages: {user_msgs}", 
                    font=("Arial", 14)).pack(pady=10)
        ctk.CTkLabel(stats_frame, text=f"System Messages: {system_msgs}", 
                    font=("Arial", 14)).pack(pady=10)
        
        if self.server and self.server.running:
            ctk.CTkLabel(stats_frame, 
                        text=f"Connected Clients: {len(self.server.clients)}", 
                        font=("Arial", 14)).pack(pady=10)
            ctk.CTkLabel(stats_frame, 
                        text=f"Total Messages Processed: {self.server.stats['total_messages']}", 
                        font=("Arial", 14)).pack(pady=10)

    def show_users(self):
        """Show connected users"""
        users_window = ctk.CTkToplevel(self)
        users_window.title("👥 Connected Users")
        users_window.geometry("500x400")
        users_window.transient(self)
        
        ctk.CTkLabel(users_window, text="👥 Connected Users", 
                    font=("Arial", 18, "bold")).pack(pady=20)
        
        users_frame = ctk.CTkScrollableFrame(users_window, fg_color="transparent")
        users_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        if self.server and self.server.running:
            if len(self.server.clients) == 0:
                ctk.CTkLabel(users_frame, text="No users connected", 
                            font=("Arial", 12), text_color="gray").pack(pady=40)
            else:
                for client_socket, info in self.server.clients.items():
                    user_card = ctk.CTkFrame(users_frame, fg_color=("#1f1f35", "#0f0f1e"), corner_radius=8)
                    user_card.pack(fill="x", pady=8, padx=5)
                    
                    left_frame = ctk.CTkFrame(user_card, fg_color="transparent")
                    left_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)
                    
                    ctk.CTkLabel(left_frame, text=f"👤 {info['nickname']}", 
                                font=("Arial", 12, "bold"), text_color="#00d4ff").pack(anchor="w")
                    ctk.CTkLabel(left_frame, text=f"📊 Messages: {info['messages_sent']}", 
                                font=("Arial", 10), text_color="#a0a0a0").pack(anchor="w", pady=(3, 0))
                    
                    right_frame = ctk.CTkFrame(user_card, fg_color="transparent")
                    right_frame.pack(side="right", padx=15, pady=10)
                    
                    ctk.CTkLabel(right_frame, text=f"🔗 {info['address'][0]}:{info['address'][1]}", 
                                font=("Arial", 9), text_color="#666666").pack()
                
                summary_frame = ctk.CTkFrame(users_window, fg_color=("#1f1f35", "#0f0f1e"), corner_radius=8)
                summary_frame.pack(pady=15, padx=20, fill="x")
                
                ctk.CTkLabel(summary_frame, text=f"Total Connected: {len(self.server.clients)} users", 
                            font=("Arial", 12, "bold"), text_color="#2ecc71").pack(pady=10)
        else:
            ctk.CTkLabel(users_frame, text="❌ Server not running", 
                        font=("Arial", 12), text_color="#e74c3c").pack(pady=40)

    def decrypt_message_dialog(self):
        """Open dialog to decrypt encrypted messages from chat"""
        decrypt_win = ctk.CTkToplevel(self)
        decrypt_win.title("🔓 Decrypt Message")
        decrypt_win.geometry("550x600")
        decrypt_win.transient(self)
        
        ctk.CTkLabel(decrypt_win, text="🔓 Decrypt Message from Chat", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # Input area
        input_frame = ctk.CTkFrame(decrypt_win)
        input_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(input_frame, text="Encrypted Message:", 
                    font=("Arial", 12, "bold")).pack(anchor="w", pady=5)
        encrypted_text = ctk.CTkTextbox(input_frame, height=120, font=("Consolas", 10))
        encrypted_text.pack(padx=10, pady=5, fill="x")
        encrypted_text.insert("1.0", "Paste encrypted message here...")
        
        # Controls
        controls = ctk.CTkFrame(decrypt_win)
        controls.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(controls, text="🔐 Algorithm:", font=("Arial", 11)).pack(side="left", padx=(0, 10))
        cipher_var = ctk.StringVar(value="Fernet")
        cipher_menu = ctk.CTkOptionMenu(controls, variable=cipher_var, values=["Fernet", "AES-256"],
                                       width=100, font=("Arial", 10))
        cipher_menu.pack(side="left", padx=10)
        
        ctk.CTkLabel(controls, text="🔑 Password:", font=("Arial", 11)).pack(side="left", padx=(20, 10))
        pwd_entry = ctk.CTkEntry(controls, placeholder_text="Enter password", 
                                show="*", width=200, font=("Arial", 10))
        pwd_entry.pack(side="left", padx=10)
        
        # Output area
        output_frame = ctk.CTkFrame(decrypt_win)
        output_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(output_frame, text="Decrypted Message:", 
                    font=("Arial", 12, "bold")).pack(anchor="w", pady=5)
        decrypted_text = ctk.CTkTextbox(output_frame, font=("Consolas", 10))
        decrypted_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        def decrypt():
            encrypted = encrypted_text.get("1.0", "end-1c").strip()
            password = pwd_entry.get()
            cipher = cipher_var.get()
            
            if not encrypted:
                messagebox.showwarning("No Input", "Please paste encrypted message")
                return
            
            if not password:
                messagebox.showwarning("Password Required", "Please enter password")
                return
            
            try:
                if cipher == "Fernet":
                    result = decrypt_fernet(encrypted, password)
                else:
                    result = decrypt_aes(encrypted, password)
                
                decrypted_text.delete("1.0", "end")
                decrypted_text.insert("1.0", result)
                self.logger.log("CHAT_DECRYPTED", f"Message decrypted using {cipher}")
                
            except ValueError:
                messagebox.showerror("Decryption Failed", "Wrong password or corrupt data")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        
        def copy_decrypted():
            text = decrypted_text.get("1.0", "end-1c")
            if text:
                self.clipboard_clear()
                self.clipboard_append(text)
                messagebox.showinfo("Copied", "Decrypted message copied to clipboard!")
        
        # Buttons
        btn_frame = ctk.CTkFrame(decrypt_win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="🔓 Decrypt", command=decrypt,
                     fg_color="#e67e22", hover_color="#d35400", width=130, height=35,
                     font=("Arial", 11, "bold")).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="📋 Copy", command=copy_decrypted,
                     width=130, height=35, font=("Arial", 11)).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Close", command=decrypt_win.destroy,
                     fg_color="#95a5a6", width=130, height=35,
                     font=("Arial", 11)).pack(side="left", padx=8)
        
    # ========== LOGS METHODS ==========
    
    # ========== ENCRYPTION TAB METHODS ==========

    # ========== ENCRYPTION TAB METHODS ==========
    def generate_password(self):
        """Generate random secure password"""
        password = generate_random_password(16)
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        self.update_password_strength()
        
    def update_password_strength(self, event=None):
        """Update password strength indicator"""
        password = self.password_entry.get()
        if not password:
            self.strength_bar.set(0)
            self.strength_label.configure(text="No Password", text_color="#ef4444")
            return
            
        score, feedback = check_password_strength(password)
        self.strength_bar.set(score / 5)
        
        texts = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
        colors = ["#ef4444", "#f59e0b", "#eab308", "#84cc16", "#22c55e", "#10b981"]
        
        self.strength_label.configure(text=texts[score], text_color=colors[score])
        
    def copy_output(self):
        """Copy output text to clipboard"""
        text = self.output_text.get("1.0", "end-1c")
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Output text copied to clipboard!")
        
    def swap_texts(self):
        """Swap input and output texts"""
        input_text = self.input_text.get("1.0", "end-1c")
        output_text = self.output_text.get("1.0", "end-1c")
        
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", output_text)
        
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", input_text)
        
    def encrypt_text(self):
        """Encrypt the input text"""
        cipher = self.cipher_choice.get()
        pwd = self.password_entry.get()
        text = self.input_text.get("1.0", "end-1c")
        
        if not text.strip():
            messagebox.showwarning("No Text", "Please enter some text to encrypt")
            return
            
        if len(text) > MAX_TEXT_SIZE:
            messagebox.showwarning("Text Too Large", f"Text exceeds maximum size of {MAX_TEXT_SIZE} characters")
            return
            
        if not pwd:
            messagebox.showwarning("Password Required", 
                                 "Please enter an encryption password")
            return
        
        try:
            validate_password(pwd)
        except ValueError as e:
            messagebox.showwarning("Invalid Password", str(e))
            return
            
        try:
            if cipher == "Fernet":
                out = encrypt_fernet(text, pwd)
            elif cipher == "AES-256":
                out = encrypt_aes(text, pwd)
            elif cipher == "ChaCha20":
                out = encrypt_chacha20(text, pwd)
            elif cipher == "Triple DES":
                out = encrypt_triple_des(text, pwd)
            elif cipher == "RC4 (CTR)":
                out = encrypt_rc4(text, pwd)
                
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", out)
            messagebox.showinfo("Success", "Text encrypted successfully!")
            self.logger.log("TEXT_ENCRYPTED", f"Text encrypted using {cipher}")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt: {str(e)}")
            
    def decrypt_text(self):
        """Decrypt the input text"""
        cipher = self.cipher_choice.get()
        pwd = self.password_entry.get()
        text = self.input_text.get("1.0", "end-1c")
        
        if not text.strip():
            messagebox.showwarning("No Text", "Please enter some text to decrypt")
            return
            
        if not pwd:
            messagebox.showwarning("Password Required", 
                                 "Please enter the decryption password")
            return
            
        try:
            if cipher == "Fernet":
                out = decrypt_fernet(text, pwd)
            elif cipher == "AES-256":
                out = decrypt_aes(text, pwd)
            elif cipher == "ChaCha20":
                out = decrypt_chacha20(text, pwd)
            elif cipher == "Triple DES":
                out = decrypt_triple_des(text, pwd)
            elif cipher == "RC4 (CTR)":
                out = decrypt_rc4(text, pwd)
                
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", out)
            messagebox.showinfo("Success", "Text decrypted successfully!")
            self.logger.log("TEXT_DECRYPTED", f"Text decrypted using {cipher}")
        except ValueError as e:
            messagebox.showerror("Decryption Error", 
                               "Decryption failed! Wrong password or corrupt data.")
        except Exception as e:
            messagebox.showerror("Decryption Error", 
                               "Decryption failed! Wrong password or corrupt data.")

    # ========== FILE TAB METHODS ==========
    def generate_file_password(self):
        """Generate password for file encryption"""
        password = generate_random_password(20)
        self.file_pwd_entry.delete(0, "end")
        self.file_pwd_entry.insert(0, password)
        
    def toggle_file_password(self):
        """Toggle file password visibility"""
        if self.file_pwd_entry.cget("show") == "*":
            self.file_pwd_entry.configure(show="")
            self.show_pwd_btn.configure(text="🙈")
        else:
            self.file_pwd_entry.configure(show="*")
            self.show_pwd_btn.configure(text="👁️")
        
    def encrypt_file(self):
        """Encrypt a selected file in a separate thread"""
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if not path:
            return
            
        pwd = self.file_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("Password Required", 
                                 "Please enter an encryption password")
            return
        
        # Run in thread
        threading.Thread(target=self._encrypt_file_worker, args=(path, pwd), daemon=True).start()

    def _encrypt_file_worker(self, path, pwd):
        """Worker function for file encryption"""
        try:
            # Check file size
            file_size = os.path.getsize(path)
            if file_size > MAX_FILE_SIZE:
                self.after(0, lambda: messagebox.showerror("File Too Large", f"File exceeds maximum size of {MAX_FILE_SIZE / 1_000_000:.0f} MB"))
                return
            
            self.after(0, lambda: (self.progress_bar.set(0), self.progress_label.configure(text="Reading file...")))
            
            with open(path, "rb") as f:
                data = f.read()
                
            file_size_mb = len(data) / 1024 / 1024  # MB
            
            self.after(0, lambda: (self.progress_bar.set(0.3), self.progress_label.configure(text="Encrypting...")))
            
            key = sha256_key(pwd)
            fernet = Fernet(fernet_key_from_bytes(key))
            encrypted_data = fernet.encrypt(data)
            
            self.after(0, lambda: (self.progress_bar.set(0.7), self.progress_label.configure(text="Saving...")))
            
            output_path = path + ".encrypted"
            with open(output_path, "wb") as f:
                f.write(encrypted_data)
                
            self.after(0, lambda: (self.progress_bar.set(1.0), self.progress_label.configure(text="Complete!")))
            
            msg = f"File encrypted successfully!\n\nOriginal: {file_size_mb:.2f} MB\nSaved as:\n{output_path}"
            self.after(0, lambda: messagebox.showinfo("Success", msg))
            self.logger.log("FILE_ENCRYPTED", f"File encrypted: {os.path.basename(path)}")
            
            self.after(2000, lambda: (self.progress_bar.set(0), 
                                     self.progress_label.configure(text="Ready")))
            
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda: (messagebox.showerror("Error", f"Encryption failed: {err_msg}"),
                                  self.progress_label.configure(text="Error!")))
            
    def decrypt_file(self):
        """Decrypt a selected file in a separate thread"""
        path = filedialog.askopenfilename(
            title="Select file to decrypt",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        if not path:
            return
            
        pwd = self.file_pwd_entry.get()
        if not pwd:
            messagebox.showwarning("Password Required", 
                                 "Please enter the decryption password")
            return
            
        # Run in thread
        threading.Thread(target=self._decrypt_file_worker, args=(path, pwd), daemon=True).start()

    def _decrypt_file_worker(self, path, pwd):
        """Worker function for file decryption"""
        try:
            self.after(0, lambda: (self.progress_bar.set(0), self.progress_label.configure(text="Reading file...")))
            
            with open(path, "rb") as f:
                data = f.read()
                
            self.after(0, lambda: (self.progress_bar.set(0.3), self.progress_label.configure(text="Decrypting...")))
            
            key = sha256_key(pwd)
            fernet = Fernet(fernet_key_from_bytes(key))
            decrypted_data = fernet.decrypt(data)
            
            self.after(0, lambda: (self.progress_bar.set(0.7), self.progress_label.configure(text="Saving...")))
            
            # Remove .encrypted extension if present
            if path.endswith(".encrypted"):
                output_path = path[:-10]
            else:
                output_path = path + ".decrypted"
                
            # If output path exists, add timestamp
            if os.path.exists(output_path):
                name, ext = os.path.splitext(output_path)
                output_path = f"{name}_{datetime.now().strftime('%H%M%S')}{ext}"
                
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
                
            self.after(0, lambda: (self.progress_bar.set(1.0), self.progress_label.configure(text="Complete!")))
            
            self.after(0, lambda: messagebox.showinfo("Success", f"File decrypted successfully!\n\nSaved as:\n{output_path}"))
            self.logger.log("FILE_DECRYPTED", f"File decrypted: {os.path.basename(path)}")
            
            self.after(2000, lambda: (self.progress_bar.set(0), 
                                     self.progress_label.configure(text="Ready")))
            
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda: (messagebox.showerror("Error", f"Decryption failed: {err_msg}"),
                                  self.progress_label.configure(text="Error!")))

    # ========== LOGS METHODS ==========
    # ========== REMOVED: Logs methods (refresh_logs, clear_logs, export_logs) ==========

    # ========== TOOLS METHODS ==========
    def tool_password_gen(self):
        """Open password generator tool - creates cryptographically secure passwords"""
        win = ctk.CTkToplevel(self)
        win.title("🎲 Password Generator")
        win.geometry("500x550")
        win.transient(self)
        
        ctk.CTkLabel(win, text="🎲 Password Generator", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # Length control
        length_frame = ctk.CTkFrame(win)
        length_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(length_frame, text="Length:", 
                    font=("Arial", 12)).pack(side="left", padx=10)
        length_var = ctk.IntVar(value=16)
        length_slider = ctk.CTkSlider(length_frame, from_=8, to=64, 
                                     variable=length_var, width=250)
        length_slider.pack(side="left", padx=10)
        length_label = ctk.CTkLabel(length_frame, textvariable=length_var, 
                                    font=("Arial", 12), width=40)
        length_label.pack(side="left", padx=10)
        
        # Quantity
        qty_frame = ctk.CTkFrame(win)
        qty_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(qty_frame, text="Quantity:", 
                    font=("Arial", 12)).pack(side="left", padx=10)
        qty_var = ctk.IntVar(value=1)
        qty_spinner = ctk.CTkOptionMenu(qty_frame, variable=qty_var,
                                       values=[str(i) for i in range(1, 11)])
        qty_spinner.pack(side="left", padx=10)
        
        # Character types
        types_frame = ctk.CTkFrame(win)
        types_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(types_frame, text="Character Types:", 
                    font=("Arial", 12)).pack(anchor="w", padx=10, pady=5)
        
        upper_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(types_frame, text="Uppercase (A-Z)", 
                       variable=upper_var).pack(anchor="w", padx=20, pady=2)
        
        lower_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(types_frame, text="Lowercase (a-z)", 
                       variable=lower_var).pack(anchor="w", padx=20, pady=2)
        
        digits_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(types_frame, text="Digits (0-9)", 
                       variable=digits_var).pack(anchor="w", padx=20, pady=2)
        
        symbols_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(types_frame, text="Symbols (!@#$%)", 
                       variable=symbols_var).pack(anchor="w", padx=20, pady=2)
        
        # Result area
        result_frame = ctk.CTkFrame(win)
        result_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(result_frame, text="Generated Passwords:", 
                    font=("Arial", 12)).pack(pady=5)
        result_text = ctk.CTkTextbox(result_frame, font=("Consolas", 11))
        result_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        def generate():
            chars = ""
            if upper_var.get(): chars += string.ascii_uppercase
            if lower_var.get(): chars += string.ascii_lowercase
            if digits_var.get(): chars += string.digits
            if symbols_var.get(): chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            if not chars:
                messagebox.showwarning("No Characters", 
                                     "Select at least one character type")
                return
            
            result_text.delete("1.0", "end")
            for i in range(qty_var.get()):
                password = ''.join(secrets.choice(chars) for _ in range(length_var.get()))
                result_text.insert("end", password + "\n")
            
        def copy_passwords():
            passwords = result_text.get("1.0", "end-1c")
            if passwords:
                self.clipboard_clear()
                self.clipboard_append(passwords)
                messagebox.showinfo("Copied", "Passwords copied to clipboard!")
                
        # Buttons
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Generate", command=generate, 
                     fg_color="#2ecc71", width=120).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Copy All", command=copy_passwords, 
                     width=120).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Close", command=win.destroy, 
                     fg_color="#95a5a6", width=120).pack(side="left", padx=10)
        
        generate()

    def tool_hash_calc(self):
        """Open hash calculator tool - computes MD5, SHA-1, SHA-256, and SHA-512 hashes"""
        win = ctk.CTkToplevel(self)
        win.title("🔢 Hash Calculator")
        win.geometry("600x550")
        win.transient(self)
        
        ctk.CTkLabel(win, text="🔢 Hash Calculator", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # Input
        input_frame = ctk.CTkFrame(win)
        input_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(input_frame, text="Input Text:", 
                    font=("Arial", 12)).pack(anchor="w", pady=5)
        input_text = ctk.CTkTextbox(input_frame, height=100, font=("Consolas", 11))
        input_text.pack(padx=10, pady=5, fill="x")
        input_text.insert("1.0", "Enter text to hash...")
        
        # Hash types (all at once)
        output_frame = ctk.CTkFrame(win)
        output_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(output_frame, text="Hash Results:", 
                    font=("Arial", 12)).pack(anchor="w", pady=5)
        output_text = ctk.CTkTextbox(output_frame, font=("Consolas", 9))
        output_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        def calculate_all_hashes():
            text = input_text.get("1.0", "end-1c")
            
            hash_results = []
            hash_results.append("=" * 60)
            hash_results.append("HASH CALCULATION RESULTS")
            hash_results.append("=" * 60)
            hash_results.append("")
            
            # MD5
            md5_hash = hashlib.md5(text.encode()).hexdigest()
            hash_results.append(f"MD5:\n{md5_hash}\n")
            
            # SHA-1
            sha1_hash = hashlib.sha1(text.encode()).hexdigest()
            hash_results.append(f"SHA-1:\n{sha1_hash}\n")
            
            # SHA-256
            sha256_hash = hashlib.sha256(text.encode()).hexdigest()
            hash_results.append(f"SHA-256:\n{sha256_hash}\n")
            
            # SHA-512
            sha512_hash = hashlib.sha512(text.encode()).hexdigest()
            hash_results.append(f"SHA-512:\n{sha512_hash}\n")
            
            output_text.delete("1.0", "end")
            output_text.insert("1.0", "\n".join(hash_results))
                
        def copy_hashes():
            hash_result = output_text.get("1.0", "end-1c")
            if hash_result:
                self.clipboard_clear()
                self.clipboard_append(hash_result)
                messagebox.showinfo("Copied", "All hashes copied to clipboard!")
                
        # Buttons
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Calculate All", command=calculate_all_hashes,
                     fg_color="#3498db", width=140).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Copy All", command=copy_hashes,
                     width=140).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Close", command=win.destroy,
                     fg_color="#95a5a6", width=140).pack(side="left", padx=10)

    def tool_base64(self):
        """Open Base64 encoder/decoder tool - encode and decode Base64 strings"""
        win = ctk.CTkToplevel(self)
        win.title("⚙️ Base64 Tool")
        win.geometry("550x550")
        win.transient(self)
        
        ctk.CTkLabel(win, text="⚙️ Base64 Encoder/Decoder", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # Input
        input_frame = ctk.CTkFrame(win)
        input_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(input_frame, text="Input:", 
                    font=("Arial", 12)).pack(anchor="w", pady=5)
        input_text = ctk.CTkTextbox(input_frame, height=140, font=("Consolas", 11))
        input_text.pack(padx=10, pady=5, fill="x")
        
        # Output
        output_frame = ctk.CTkFrame(win)
        output_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(output_frame, text="Output:", 
                    font=("Arial", 12)).pack(anchor="w", pady=5)
        output_text = ctk.CTkTextbox(output_frame, font=("Consolas", 10))
        output_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        def encode_base64():
            text = input_text.get("1.0", "end-1c")
            try:
                encoded = base64.b64encode(text.encode()).decode()
                output_text.delete("1.0", "end")
                output_text.insert("1.0", encoded)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to encode: {str(e)}")
                
        def decode_base64():
            text = input_text.get("1.0", "end-1c")
            try:
                decoded = base64.b64decode(text.encode()).decode()
                output_text.delete("1.0", "end")
                output_text.insert("1.0", decoded)
            except Exception as e:
                messagebox.showerror("Error", "Invalid Base64 data")
                
        def copy_output():
            text = output_text.get("1.0", "end-1c")
            if text:
                self.clipboard_clear()
                self.clipboard_append(text)
                messagebox.showinfo("Copied", "Output copied to clipboard!")
                
        # Buttons
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Encode", command=encode_base64,
                     fg_color="#2ecc71", width=110).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Decode", command=decode_base64,
                     fg_color="#e67e22", width=110).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Copy", command=copy_output,
                     width=110).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Close", command=win.destroy,
                     fg_color="#95a5a6", width=110).pack(side="left", padx=5)

    def tool_qr_generator(self):
        """Open QR code generator tool - creates QR codes from text and URLs"""
        win = ctk.CTkToplevel(self)
        win.title("📱 QR Code Generator")
        win.geometry("550x650")
        win.transient(self)
        
        ctk.CTkLabel(win, text="📱 QR Code Generator", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # Input
        input_frame = ctk.CTkFrame(win)
        input_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(input_frame, text="Enter Text or URL:", 
                    font=("Arial", 12)).pack(anchor="w", pady=5)
        input_text = ctk.CTkTextbox(input_frame, height=80, font=("Arial", 11))
        input_text.pack(padx=10, pady=5, fill="x")
        input_text.insert("1.0", "https://example.com")
        
        # QR display
        qr_frame = ctk.CTkFrame(win, fg_color=("white", "gray20"))
        qr_frame.pack(pady=15, padx=20, fill="both", expand=True)
        
        qr_label = ctk.CTkLabel(qr_frame, text="Generate a QR code", 
                               font=("Arial", 12))
        qr_label.pack(expand=True)
        
        def generate_qr():
            text = input_text.get("1.0", "end-1c").strip()
            if not text:
                messagebox.showwarning("No Input", "Please enter text or URL")
                return
                
            try:
                qr = qrcode.QRCode(version=1, box_size=10, border=4)
                qr.add_data(text)
                qr.make(fit=True)
                
                # Generate QR code image
                qr_img = qr.make_image(fill_color="black", back_color="white")
                # type: ignore - qrcode library returns PIL Image at runtime
                photo = ImageTk.PhotoImage(qr_img)  # type: ignore
                qr_label.configure(image=photo, text="")
                # Store reference to prevent garbage collection using setattr
                setattr(qr_label, '_qr_photo', photo)
                
                # Store for saving (store as label attribute)
                setattr(qr_label, '_qr_image_data', qr_img)
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate QR code: {str(e)}")
                
        def save_qr():
            if not hasattr(qr_label, '_qr_image_data'):
                messagebox.showwarning("No QR Code", "Generate a QR code first")
                return
                
            filename = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
                title="Save QR Code"
            )
            
            if filename:
                try:
                    getattr(qr_label, '_qr_image_data').save(filename)
                    messagebox.showinfo("Success", "QR code saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save: {str(e)}")
                
        # Buttons
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Generate", command=generate_qr,
                     fg_color="#2ecc71", width=130).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Save Image", command=save_qr,
                     width=130).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Close", command=win.destroy,
                     fg_color="#95a5a6", width=130).pack(side="left", padx=8)

    def tool_text_analyzer(self):
        """Open text analyzer tool - analyzes text statistics and character counts"""
        win = ctk.CTkToplevel(self)
        win.title("📊 Text Analyzer")
        win.geometry("600x600")
        win.transient(self)
        
        ctk.CTkLabel(win, text="📊 Text Analyzer", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # Input
        input_frame = ctk.CTkFrame(win)
        input_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(input_frame, text="Enter Text to Analyze:", 
                    font=("Arial", 12)).pack(anchor="w", pady=5)
        input_text = ctk.CTkTextbox(input_frame, font=("Arial", 11))
        input_text.pack(padx=10, pady=5, fill="both", expand=True)
        input_text.insert("1.0", "Enter or paste your text here for analysis...")
        
        # Results
        results_frame = ctk.CTkFrame(win)
        results_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(results_frame, text="Analysis Results:", 
                    font=("Arial", 12, "bold")).pack(anchor="w", pady=5)
        
        results_text = ctk.CTkTextbox(results_frame, height=200, font=("Consolas", 10))
        results_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        def analyze_text():
            text = input_text.get("1.0", "end-1c")
            
            # Calculations
            char_count = len(text)
            char_no_spaces = len(text.replace(" ", "").replace("\n", "").replace("\t", ""))
            word_count = len(text.split())
            line_count = text.count("\n") + 1
            sentence_count = text.count(".") + text.count("!") + text.count("?")
            
            # Character frequency
            char_freq = {}
            for char in text.lower():
                if char.isalnum():
                    char_freq[char] = char_freq.get(char, 0) + 1
            
            # Most common characters
            top_chars = sorted(char_freq.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Average word length
            words = text.split()
            avg_word_len = sum(len(word) for word in words) / len(words) if words else 0
            
            # Build results
            results = []
            results.append("=" * 50)
            results.append("TEXT ANALYSIS RESULTS")
            results.append("=" * 50)
            results.append("")
            results.append(f"Total Characters: {char_count}")
            results.append(f"Characters (no spaces): {char_no_spaces}")
            results.append(f"Words: {word_count}")
            results.append(f"Lines: {line_count}")
            results.append(f"Sentences: {sentence_count}")
            results.append(f"Average Word Length: {avg_word_len:.2f} characters")
            results.append("")
            results.append("Top 5 Most Common Characters:")
            for char, count in top_chars:
                results.append(f"  '{char}': {count} times")
            results.append("")
            results.append(f"Estimated Reading Time: {word_count // 200} minutes")
            
            results_text.delete("1.0", "end")
            results_text.insert("1.0", "\n".join(results))
            
        def copy_results():
            results = results_text.get("1.0", "end-1c")
            if results:
                self.clipboard_clear()
                self.clipboard_append(results)
                messagebox.showinfo("Copied", "Results copied to clipboard!")
        
        # Buttons
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Analyze", command=analyze_text,
                     fg_color="#3498db", width=130).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Copy Results", command=copy_results,
                     width=130).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Close", command=win.destroy,
                     fg_color="#95a5a6", width=130).pack(side="left", padx=8)

    def tool_uuid_generator(self):
        """Open UUID generator tool - generates cryptographically unique identifiers"""
        win = ctk.CTkToplevel(self)
        win.title("🆔 UUID Generator")
        win.geometry("550x450")
        win.transient(self)
        
        ctk.CTkLabel(win, text="🆔 UUID Generator", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        ctk.CTkLabel(win, text="Generate Universally Unique Identifiers", 
                    font=("Arial", 11), text_color="gray").pack(pady=5)
        
        # Quantity
        qty_frame = ctk.CTkFrame(win)
        qty_frame.pack(pady=15, padx=20, fill="x")
        
        ctk.CTkLabel(qty_frame, text="Quantity:", 
                    font=("Arial", 12)).pack(side="left", padx=10)
        qty_var = ctk.IntVar(value=5)
        qty_slider = ctk.CTkSlider(qty_frame, from_=1, to=20, 
                                  variable=qty_var, width=250)
        qty_slider.pack(side="left", padx=10)
        qty_label = ctk.CTkLabel(qty_frame, textvariable=qty_var, 
                                font=("Arial", 12), width=40)
        qty_label.pack(side="left", padx=10)
        
        # Results
        results_frame = ctk.CTkFrame(win)
        results_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(results_frame, text="Generated UUIDs:", 
                    font=("Arial", 12)).pack(anchor="w", pady=5)
        results_text = ctk.CTkTextbox(results_frame, font=("Consolas", 10))
        results_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        def generate_uuids():
            import uuid
            results_text.delete("1.0", "end")
            for i in range(qty_var.get()):
                new_uuid = str(uuid.uuid4())
                results_text.insert("end", new_uuid + "\n")
                
        def copy_uuids():
            uuids = results_text.get("1.0", "end-1c")
            if uuids:
                self.clipboard_clear()
                self.clipboard_append(uuids)
                messagebox.showinfo("Copied", "UUIDs copied to clipboard!")
        
        # Buttons
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Generate", command=generate_uuids,
                     fg_color="#2ecc71", width=130).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Copy All", command=copy_uuids,
                     width=130).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Close", command=win.destroy,
                     fg_color="#95a5a6", width=130).pack(side="left", padx=10)
        
        generate_uuids()

    def tool_color_picker(self):
        """Open color picker tool - picks colors with hex and RGB output"""
        win = ctk.CTkToplevel(self)
        win.title("🎨 Color Picker")
        win.geometry("500x550")
        win.transient(self)
        
        ctk.CTkLabel(win, text="🎨 Color Picker", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # Color display
        color_display = ctk.CTkFrame(win, height=150, fg_color="#3498db")
        color_display.pack(pady=15, padx=20, fill="x")
        color_display.pack_propagate(False)
        
        color_label = ctk.CTkLabel(color_display, text="Click 'Pick Color' to choose", 
                                   font=("Arial", 14, "bold"), text_color="white")
        color_label.pack(expand=True)
        
        # Color info
        info_frame = ctk.CTkFrame(win)
        info_frame.pack(pady=10, padx=20, fill="x")
        
        hex_var = tk.StringVar(value="#3498db")
        rgb_var = tk.StringVar(value="RGB(52, 152, 219)")
        
        ctk.CTkLabel(info_frame, text="Hex Code:", 
                    font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=8, sticky="w")
        hex_entry = ctk.CTkEntry(info_frame, textvariable=hex_var, width=200, font=("Consolas", 12))
        hex_entry.grid(row=0, column=1, padx=10, pady=8)
        
        ctk.CTkLabel(info_frame, text="RGB Code:", 
                    font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=8, sticky="w")
        rgb_entry = ctk.CTkEntry(info_frame, textvariable=rgb_var, width=200, font=("Consolas", 12))
        rgb_entry.grid(row=1, column=1, padx=10, pady=8)
        
        def pick_color():
            color = colorchooser.askcolor(title="Choose a color")
            if color[1]:
                hex_color = color[1]
                rgb_color = color[0]
                
                if rgb_color is not None:
                    color_display.configure(fg_color=hex_color)
                    hex_var.set(hex_color)
                    rgb_var.set(f"RGB({int(rgb_color[0])}, {int(rgb_color[1])}, {int(rgb_color[2])})")
                    
                    # Adjust text color for contrast
                    brightness = (int(rgb_color[0]) * 299 + int(rgb_color[1]) * 587 + int(rgb_color[2]) * 114) / 1000
                    text_color = "black" if brightness > 128 else "white"
                    color_label.configure(text=hex_color, text_color=text_color)
                
        def copy_hex():
            self.clipboard_clear()
            self.clipboard_append(hex_var.get())
            messagebox.showinfo("Copied", "Hex code copied!")
            
        def copy_rgb():
            self.clipboard_clear()
            self.clipboard_append(rgb_var.get())
            messagebox.showinfo("Copied", "RGB code copied!")
        
        # Buttons
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Pick Color", command=pick_color,
                     fg_color="#2ecc71", width=120).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Copy Hex", command=copy_hex,
                     width=120).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Copy RGB", command=copy_rgb,
                     width=120).pack(side="left", padx=8)
        
        ctk.CTkButton(win, text="Close", command=win.destroy,
                     fg_color="#95a5a6", width=150).pack(pady=10)

    def tool_checksum(self):
        """Open file checksum calculator - computes MD5, SHA-1, and SHA-256 checksums"""
        win = ctk.CTkToplevel(self)
        win.title("✅ File Checksum Calculator")
        win.geometry("600x500")
        win.transient(self)
        
        ctk.CTkLabel(win, text="✅ File Checksum Calculator", 
                    font=("Arial", 18, "bold")).pack(pady=15)
        
        # File selection
        file_frame = ctk.CTkFrame(win)
        file_frame.pack(pady=10, padx=20, fill="x")
        
        file_var = tk.StringVar(value="No file selected")
        ctk.CTkLabel(file_frame, textvariable=file_var, 
                    font=("Arial", 11), text_color="gray").pack(pady=10)
        
        selected_file = []
        
        def select_file():
            filepath = filedialog.askopenfilename(title="Select file for checksum")
            if filepath:
                if selected_file:
                    selected_file[0] = filepath
                else:
                    selected_file.append(filepath)
                file_var.set(os.path.basename(filepath))
                
        ctk.CTkButton(file_frame, text="Select File", command=select_file,
                     width=150).pack(pady=5)
        
        # Results
        results_frame = ctk.CTkFrame(win)
        results_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(results_frame, text="Checksums:", 
                    font=("Arial", 12, "bold")).pack(anchor="w", pady=5)
        results_text = ctk.CTkTextbox(results_frame, font=("Consolas", 9))
        results_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        # Progress
        progress = ctk.CTkProgressBar(win, width=400)
        progress.pack(pady=10)
        progress.set(0)
        
        def calculate_checksums():
            if not selected_file[0]:
                messagebox.showwarning("No File", "Please select a file first")
                return
                
            try:
                progress.set(0)
                results_text.delete("1.0", "end")
                results_text.insert("end", "Calculating checksums...\n\n")
                win.update()
                
                with open(selected_file[0], 'rb') as f:
                    data = f.read()
                
                progress.set(0.25)
                win.update()
                
                md5 = hashlib.md5(data).hexdigest()
                progress.set(0.5)
                win.update()
                
                sha1 = hashlib.sha1(data).hexdigest()
                progress.set(0.75)
                win.update()
                
                sha256 = hashlib.sha256(data).hexdigest()
                progress.set(1.0)
                
                results = []
                results.append("=" * 60)
                results.append(f"File: {os.path.basename(selected_file[0])}")
                results.append(f"Size: {len(data) / 1024:.2f} KB")
                results.append("=" * 60)
                results.append("")
                results.append(f"MD5:\n{md5}\n")
                results.append(f"SHA-1:\n{sha1}\n")
                results.append(f"SHA-256:\n{sha256}\n")
                
                results_text.delete("1.0", "end")
                results_text.insert("1.0", "\n".join(results))
                
            except IOError as e:
                messagebox.showerror("Error", f"Could not read file: {str(e)}")
                progress.set(0)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to calculate: {str(e)}")
                progress.set(0)
        
        
    def show_quick_stats(self):
        """Show quick statistics in a small popup"""
        stats_window = ctk.CTkToplevel(self)
        stats_window.title("⚡ Quick Stats")
        stats_window.geometry("400x300")
        stats_window.resizable(False, False)
        stats_window.transient(self)
        
        # Header
        header = ctk.CTkFrame(stats_window, fg_color="#2d3561", height=50)
        header.pack(fill="x", padx=0, pady=0)
        header.pack_propagate(False)
        
        ctk.CTkLabel(header, text="📊 Application Statistics", 
                    font=("Arial", 14, "bold"), text_color="#00d4ff").pack(pady=12)
        
        # Content frame
        content = ctk.CTkFrame(stats_window, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Stats
        stats = []
        stats.append(("Total Messages", len(self.chat_messages)))
        stats.append(("Chat Status", "Connected" if self.client else "Disconnected"))
        stats.append(("Server Status", f"Running ({len(self.server.clients) if self.server else 0} clients)" if (self.server and self.server.running) else "Stopped"))
        stats.append(("Total Logs", len(self.logger.logs)))
        
        for stat_name, stat_value in stats:
            stat_frame = ctk.CTkFrame(content, fg_color=("#1f1f35", "#0f0f1e"), corner_radius=5)
            stat_frame.pack(fill="x", pady=8)
            
            ctk.CTkLabel(stat_frame, text=stat_name, font=("Arial", 11), text_color="#a0a0a0").pack(anchor="w", padx=12, pady=(8, 2))
            ctk.CTkLabel(stat_frame, text=str(stat_value), font=("Arial", 13, "bold"), text_color="#00d4ff").pack(anchor="w", padx=12, pady=(2, 8))

    def show_chat_context_menu(self, event):
        """Show right-click context menu for chat decryption"""
        try:
            # Get selected text
            sel_start = self.chat_box.tag_ranges("sel")
            if sel_start:
                selected_text = self.chat_box.get(sel_start[0], sel_start[1])
                selected_text = selected_text.strip()
            else:
                messagebox.showinfo("No Selection", "Please select the encrypted message first")
                return
            
            # Create context menu
            context_menu = tk.Menu(self, tearoff=0)
            context_menu.add_command(label="🔓 Decrypt Selected", 
                                   command=lambda: self.decrypt_selected_message(selected_text))
            context_menu.add_separator()
            context_menu.add_command(label="📋 Copy", 
                                   command=lambda: (self.clipboard_clear(), self.clipboard_append(selected_text)))
            
            # Show menu at cursor position
            context_menu.post(event.x_root, event.y_root)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error showing context menu: {str(e)}")
    
    def decrypt_selected_message(self, encrypted_message):
        """Decrypt selected message inline"""
        decrypt_win = ctk.CTkToplevel(self)
        decrypt_win.title("🔓 Decrypt Message")
        decrypt_win.geometry("500x500")
        decrypt_win.transient(self)
        
        ctk.CTkLabel(decrypt_win, text="🔓 Decrypt Selected Message", 
                    font=("Arial", 16, "bold")).pack(pady=10)
        
        # Display encrypted message
        info_frame = ctk.CTkFrame(decrypt_win)
        info_frame.pack(pady=5, padx=20, fill="x")
        
        ctk.CTkLabel(info_frame, text="Encrypted:", font=("Arial", 11, "bold")).pack(anchor="w", pady=3)
        ctk.CTkLabel(info_frame, text=encrypted_message[:80] + ("..." if len(encrypted_message) > 80 else ""),
                    font=("Consolas", 9), text_color="#999999", wraplength=400).pack(anchor="w", padx=10)
        
        # Controls
        controls = ctk.CTkFrame(decrypt_win)
        controls.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(controls, text="Algorithm:", font=("Arial", 11)).pack(side="left", padx=(0, 10))
        cipher_var = ctk.StringVar(value="Fernet")
        ctk.CTkOptionMenu(controls, variable=cipher_var, values=["Fernet", "AES-256"],
                         width=100).pack(side="left", padx=10)
        
        ctk.CTkLabel(controls, text="Password:", font=("Arial", 11)).pack(side="left", padx=(20, 10))
        pwd_entry = ctk.CTkEntry(controls, placeholder_text="Enter password", 
                                show="*", width=180, font=("Arial", 10))
        pwd_entry.pack(side="left", padx=10)
        
        # Result
        result_frame = ctk.CTkFrame(decrypt_win)
        result_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(result_frame, text="Decrypted Message:", 
                    font=("Arial", 11, "bold")).pack(anchor="w", pady=3)
        result_text = ctk.CTkTextbox(result_frame, font=("Consolas", 10))
        result_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        def decrypt():
            password = pwd_entry.get()
            cipher = cipher_var.get()
            
            if not password:
                messagebox.showwarning("No Password", "Please enter password")
                return
            
            try:
                if cipher == "Fernet":
                    result = decrypt_fernet(encrypted_message, password)
                else:
                    result = decrypt_aes(encrypted_message, password)
                
                result_text.delete("1.0", "end")
                result_text.insert("1.0", result)
                self.logger.log("CHAT_DECRYPTED", f"Message decrypted in chat using {cipher}")
                
            except ValueError:
                messagebox.showerror("Failed", "Wrong password or corrupt data")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        
        def copy_result():
            text = result_text.get("1.0", "end-1c")
            if text:
                self.clipboard_clear()
                self.clipboard_append(text)
                messagebox.showinfo("Copied", "Decrypted message copied!")
        
        # Buttons
        btn_frame = ctk.CTkFrame(decrypt_win)
        btn_frame.pack(pady=12)
        
        ctk.CTkButton(btn_frame, text="🔓 Decrypt", command=decrypt,
                     fg_color="#e67e22", width=120, height=35,
                     font=("Arial", 11, "bold")).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📋 Copy", command=copy_result,
                     width=120, height=35).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Close", command=decrypt_win.destroy,
                     fg_color="#95a5a6", width=120, height=35).pack(side="left", padx=5)

    def on_closing(self):
        """Handle application closing cleanly."""
        self._closing = True          # stop all poll loops immediately
        self.save_config()
        try:
            self.stop_server()
        except Exception:
            pass
        try:
            self.disconnect()
        except Exception:
            pass
        # Log shutdown to MongoDB if connected
        try:
            if self.mongo_manager and self.mongo_manager.connected and self.current_user:
                self.mongo_manager.save_log(
                    "App closed", level="INFO", source="app",
                    user=self.current_user.get("username", "SYSTEM"))
        except Exception:
            pass
        self.destroy()

    def _update_char_count(self):
        """Update character count for chat messages"""
        if hasattr(self, 'msg_entry') and hasattr(self, 'char_count_label'):
            count = len(self.msg_entry.get())
            self.char_count_label.configure(text=f"{count}/{MESSAGE_MAX_SIZE}")

# ========== MAIN ENTRY POINT ==========
if __name__ == "__main__":
    try:
        app = CipherCoreApp()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        import traceback
        traceback.print_exc()
        
