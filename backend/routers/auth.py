import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import User, get_session
from models.schemas import APIResponse

router = APIRouter(prefix="/api/auth")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("JWT_SECRET", "vultron-secret-key-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 7


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


def create_token(user_id: int, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {"user_id": user_id, "email": email, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def verify_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


@router.post("/register")
async def register(request: RegisterRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == request.email))
    if result.scalar_one_or_none():
        return APIResponse.error("EMAIL_EXISTS", "Email already registered")

    user = User(email=request.email, password_hash=pwd_context.hash(request.password))
    session.add(user)
    await session.commit()
    await session.refresh(user)

    token = create_token(user.id, user.email)
    return APIResponse.success({"token": token, "email": user.email, "user_id": user.id})


@router.post("/login")
async def login(request: LoginRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    if not user or not pwd_context.verify(request.password, user.password_hash):
        return APIResponse.error("INVALID_CREDENTIALS", "Invalid email or password")

    token = create_token(user.id, user.email)
    return APIResponse.success({"token": token, "email": user.email, "user_id": user.id})


@router.get("/me")
async def get_me(authorization: Optional[str] = Header(None), session: AsyncSession = Depends(get_session)):
    if not authorization or not authorization.startswith("Bearer "):
        return APIResponse.error("UNAUTHORIZED", "Not logged in")

    payload = verify_token(authorization.removeprefix("Bearer "))
    if not payload:
        return APIResponse.error("INVALID_TOKEN", "Token expired or invalid")

    result = await session.execute(select(User).where(User.id == payload["user_id"]))
    user = result.scalar_one_or_none()
    if not user:
        return APIResponse.error("NOT_FOUND", "User not found")

    return APIResponse.success({
        "user_id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    })


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.patch("/password")
async def change_password(
    request: ChangePasswordRequest,
    authorization: Optional[str] = Header(None),
    session: AsyncSession = Depends(get_session),
):
    if not authorization or not authorization.startswith("Bearer "):
        return APIResponse.error("UNAUTHORIZED", "Not logged in")

    payload = verify_token(authorization.removeprefix("Bearer "))
    if not payload:
        return APIResponse.error("INVALID_TOKEN", "Token expired or invalid")

    if len(request.new_password) < 8:
        return APIResponse.error("WEAK_PASSWORD", "New password must be at least 8 characters")

    result = await session.execute(select(User).where(User.id == payload["user_id"]))
    user = result.scalar_one_or_none()
    if not user:
        return APIResponse.error("NOT_FOUND", "User not found")

    if not pwd_context.verify(request.current_password, user.password_hash):
        return APIResponse.error("WRONG_PASSWORD", "Current password is incorrect")

    user.password_hash = pwd_context.hash(request.new_password)
    await session.commit()

    return APIResponse.success({"message": "Password updated successfully"})
