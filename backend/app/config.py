import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv("C:/Users/zahid muhammed/Desktop/pass_less_auth/backend/.env")

SECRET_KEY = os.getenv("JWT_SECRET", "default-secret-key-for-development-only-12345")
ALGORITHM = "HS256"
FERNET_KEY = os.getenv("FERNET_KEY", Fernet.generate_key())

print(f"[config.py] SECRET_KEY: {SECRET_KEY}")