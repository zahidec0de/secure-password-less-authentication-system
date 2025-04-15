from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from app.auth import AuthService
from app.database import get_db, Base, engine
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import jwt
from app.config import SECRET_KEY, ALGORITHM
from app import models
from collections import defaultdict
from datetime import datetime, timedelta

app = FastAPI()
auth_service = AuthService()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8001"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

print("Creating database tables...")
Base.metadata.create_all(bind=engine, checkfirst=True)
print("Database tables created.")

login_attempts = defaultdict(list)

class RegisterRequest(BaseModel):
    email: str
    phone: str
    cpr: str
    answer1: str
    answer2: str

class LoginInitiateRequest(BaseModel):
    cpr: str
    method: str

class LoginVerifyRequest(BaseModel):
    cpr: str
    method: str
    data: dict

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, register_request: RegisterRequest, db: Session = Depends(get_db)):
    return await auth_service.register_user(
        register_request.email,
        register_request.phone,
        register_request.cpr,
        register_request.answer1,
        register_request.answer2,
        db
    )

@app.get("/verify-email")
async def verify_email(token: str, db: Session = Depends(get_db)):
    return await auth_service.verify_email(token, db)

@app.post("/login/initiate")
@limiter.limit("5/minute")
async def initiate_login(request: Request, login_request: LoginInitiateRequest, db: Session = Depends(get_db)):
    client_ip = request.client.host
    cpr = login_request.cpr

    # Check CPR-based rate limit
    now = datetime.utcnow()
    login_attempts[cpr] = [t for t in login_attempts[cpr] if now - t < timedelta(minutes=1)]
    if len(login_attempts[cpr]) >= 5:
        raise HTTPException(status_code=429, detail="Too many login attempts for this CPR. Please try again later.")
    login_attempts[cpr].append(now)

    print(f"Login attempt from IP: {client_ip}")
    return await auth_service.initiate_login(login_request.cpr, login_request.method, db)

@app.post("/login/verify")
@limiter.limit("5/minute")
async def verify_login(request: Request, verify_request: LoginVerifyRequest, db: Session = Depends(get_db)):
    result = await auth_service.verify_login(verify_request.cpr, verify_request.method, verify_request.data, db)
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=result["access_token"],
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=15*60  # 15 minutes
    )
    return response

@app.get("/login/magic")
async def verify_magic_link(token: str, db: Session = Depends(get_db)):
    print(f"[main.py] Received token (hidden)")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["user_id"]
        print(f"[main.py] Decoded user_id: {user_id}")
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        cpr = auth_service.decrypt_field(user.cpr)
    except jwt.ExpiredSignatureError:
        return RedirectResponse(url="http://127.0.0.1:8001/index.html?error=Magic%20link%20expired")
    except jwt.InvalidTokenError as e:
        print(f"[main.py] Invalid token error (details hidden)")
        return RedirectResponse(url="http://127.0.0.1:8001/index.html?error=Invalid%20magic%20link")

    verify_request = LoginVerifyRequest(
        cpr=cpr,
        method="magic_link",
        data={"token": token}
    )
    await auth_service.verify_login(verify_request.cpr, verify_request.method, verify_request.data, db)
    return RedirectResponse(url="http://127.0.0.1:8001/dashboard.html")

token_blacklist = set()

@app.post("/logout")
async def logout(request: Request):
    token = request.cookies.get("access_token")
    if token:
        token_blacklist.add(token)
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie("access_token")
    return response