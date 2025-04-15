from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
import jwt
import secrets
from datetime import datetime, timedelta
import bcrypt
import re
from app.config import SECRET_KEY, ALGORITHM, FERNET_KEY
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
import base64
import hashlib

CIPHER = Fernet(FERNET_KEY)

# AES encryption key (must match frontend)
ENCRYPTION_KEY = "4Up82wHUdKR68-fS8KWVf3AAyA99AEKO".encode('utf-8')  # 32 bytes for AES-256

otp_storage = {}
magic_link_storage = {}

class AuthService:
    def __init__(self):
        pass

    def encrypt_field(self, data: str) -> str:
        return CIPHER.encrypt(data.encode()).decode()

    def decrypt_field(self, encrypted_data: str) -> str:
        return CIPHER.decrypt(encrypted_data.encode()).decode()

    def evp_bytes_to_key(self, password: bytes, salt: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
        d = b""
        d_i = b""
        while len(d) < key_len + iv_len:
            d_i = hashlib.md5(d_i + password + salt).digest()
            d += d_i
        key = d[:key_len]
        iv = d[key_len:key_len + iv_len]
        return key, iv

    def decrypt_aes(self, encrypted_data: str) -> str:
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            if encrypted_bytes[:8] != b"Salted__":
                raise ValueError("Invalid encrypted data format: missing 'Salted__' prefix")
            salt = encrypted_bytes[8:16]
            ciphertext = encrypted_bytes[16:]
            key, iv = self.evp_bytes_to_key(ENCRYPTION_KEY, salt, key_len=32, iv_len=16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            padding_length = decrypted[-1]
            if padding_length > 16 or padding_length < 1:
                raise ValueError("Invalid padding length")
            if decrypted[-padding_length:] != bytes([padding_length] * padding_length):
                raise ValueError("Invalid padding")
            decrypted = decrypted[:-padding_length]
            return decrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def hash_answer(self, answer: str) -> str:
        return bcrypt.hashpw(answer.lower().encode(), bcrypt.gensalt(rounds=14)).decode()

    def verify_answer(self, answer: str, hashed_answer: str) -> bool:
        return bcrypt.checkpw(answer.lower().encode(), hashed_answer.encode())

    def validate_cpr(self, cpr: str) -> bool:
        cpr = cpr.strip()
        if not re.match(r"^[0-9]{6}$", cpr):
            raise HTTPException(status_code=400, detail="Invalid CPR format. Must be a 6-digit number.")
        return True

    def validate_email(self, email: str) -> bool:
        email = email.strip()
        if len(email) > 255:
            raise HTTPException(status_code=400, detail="Email too long")
        return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

    def validate_phone(self, phone: str) -> bool:
        phone = phone.strip()
        if len(phone) > 15:
            raise HTTPException(status_code=400, detail="Phone number too long")
        return bool(re.match(r"^[0-9]+$", phone))

    async def register_user(self, email: str, phone: str, cpr: str, answer1: str, answer2: str, db: Session):
        try:
            email = self.decrypt_aes(email)
            phone = self.decrypt_aes(phone)
            cpr = self.decrypt_aes(cpr)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid encrypted data: {str(e)}")

        self.validate_cpr(cpr)
        if not self.validate_email(email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        if not self.validate_phone(phone):
            raise HTTPException(status_code=400, detail="Invalid phone number format")
        if len(answer1) < 3 or len(answer2) < 3:
            raise HTTPException(status_code=400, detail="Security answers must be at least 3 characters")

        encrypted_email = self.encrypt_field(email)
        encrypted_phone = self.encrypt_field(phone)
        encrypted_cpr = self.encrypt_field(cpr)

        existing_users = db.query(User).all()
        for user in existing_users:
            if self.decrypt_field(user.email) == email:
                raise HTTPException(status_code=400, detail="Email already registered")
            if self.decrypt_field(user.phone) == phone:
                raise HTTPException(status_code=400, detail="Phone number already registered")
            if self.decrypt_field(user.cpr) == cpr:
                raise HTTPException(status_code=400, detail="CPR already registered")

        hashed_answer1 = self.hash_answer(answer1)
        hashed_answer2 = self.hash_answer(answer2)

        user = User(
            email=encrypted_email,
            phone=encrypted_phone,
            cpr=encrypted_cpr,
            security_answer1=hashed_answer1,
            security_answer2=hashed_answer2
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        verification_token = jwt.encode(
            {"user_id": user.id, "exp": datetime.utcnow() + timedelta(minutes=5)},
            SECRET_KEY,
            algorithm=ALGORITHM
        )
        verification_url = f"http://127.0.0.1:8000/verify-email?token={verification_token}"
        print(f"Verification URL for user {user.id}: {verification_url}")
        return {"user_id": user.id}

    async def verify_email(self, token: str, db: Session):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload["user_id"]
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            print(f"[{datetime.utcnow()}] Email verified for user {user_id}")
            return {"message": "Email verified successfully"}
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Verification link expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid verification link")

    async def initiate_login(self, cpr: str, method: str, db: Session):
        try:
            cpr = self.decrypt_aes(cpr)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid encrypted CPR: {str(e)}")

        self.validate_cpr(cpr)

        user = None
        for u in db.query(User).all():
            decrypted_cpr = self.decrypt_field(u.cpr)
            if decrypted_cpr == cpr:
                user = u
                break

        if not user:
            raise HTTPException(status_code=401, detail="Invalid CPR or login method. Please try again.")

        if method == "magic_link":
            token = jwt.encode(
                {"user_id": user.id, "exp": datetime.utcnow() + timedelta(minutes=5)},
                SECRET_KEY,
                algorithm=ALGORITHM
            )
            magic_link_storage[cpr] = {"token": token, "expires": datetime.utcnow() + timedelta(minutes=5)}
            magic_url = f"http://127.0.0.1:8000/login/magic?token={token}"
            print(f"Magic Link for CPR (hidden): {magic_url}")
            return {"message": "Magic link generated. Check the server console."}
        
        elif method == "otp_sms":
            otp = f"{secrets.randbelow(1000000):06d}"  # Secure 6-digit OTP
            otp_storage[cpr] = {"otp": otp, "expires": datetime.utcnow() + timedelta(minutes=5), "attempts": 0}
            print(f"OTP for CPR (hidden): {otp}")
            return {"message": "OTP generated. Check the server console."}
        
        elif method == "security_questions":
            return {"message": "Answer your security questions to log in."}
        
        else:
            raise HTTPException(status_code=400, detail="Invalid login method")

    async def verify_login(self, cpr: str, method: str, data: dict, db: Session):
        if method != "magic_link":
            try:
                cpr = self.decrypt_aes(cpr)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid encrypted CPR: {str(e)}")

        user = None
        for u in db.query(User).all():
            decrypted_cpr = self.decrypt_field(u.cpr)
            if decrypted_cpr == cpr:
                user = u
                break

        if not user:
            raise HTTPException(status_code=401, detail="Invalid CPR or login method. Please try again.")

        if method == "magic_link":
            token = data.get("token")
            print(f"[auth.py] Verifying token for CPR (hidden)")
            if cpr not in magic_link_storage:
                raise HTTPException(status_code=400, detail="Magic link not found or expired")
            stored_token = magic_link_storage[cpr]
            if datetime.utcnow() > stored_token["expires"]:
                del magic_link_storage[cpr]
                raise HTTPException(status_code=400, detail="Magic link expired")
            if token != stored_token["token"]:
                print(f"[auth.py] Token mismatch (details hidden)")
                raise HTTPException(status_code=401, detail="Invalid magic link")
            del magic_link_storage[cpr]

        elif method == "otp_sms":
            otp = data.get("otp")
            if cpr not in otp_storage:
                raise HTTPException(status_code=400, detail="OTP not found or expired")
            stored_otp = otp_storage[cpr]
            if datetime.utcnow() > stored_otp["expires"]:
                del otp_storage[cpr]
                raise HTTPException(status_code=400, detail="OTP expired")
            stored_otp["attempts"] = stored_otp.get("attempts", 0) + 1
            if stored_otp["attempts"] >= 3:
                del otp_storage[cpr]
                raise HTTPException(status_code=401, detail="Too many incorrect OTP attempts")
            if otp != stored_otp["otp"]:
                raise HTTPException(status_code=401, detail="Invalid OTP")
            del otp_storage[cpr]

        elif method == "security_questions":
            answer1 = data.get("answer1")
            answer2 = data.get("answer2")
            if not self.verify_answer(answer1, user.security_answer1) or not self.verify_answer(answer2, user.security_answer2):
                raise HTTPException(status_code=401, detail="Incorrect answers to security questions")

        else:
            raise HTTPException(status_code=400, detail="Invalid login method")

        payload = {
            "sub": str(user.id),
            "exp": datetime.utcnow() + timedelta(minutes=15)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        
        print(f"[{datetime.utcnow()}] Login successful for user (CPR hidden) via {method}")
        return {"access_token": token, "token_type": "bearer"}