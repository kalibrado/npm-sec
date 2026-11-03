from typing import Optional
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UserPasswordUpdate(BaseModel):
    password: str


class TrustedEntry(BaseModel):
    type: str
    value: str
    reason: Optional[str] = ""


class BlockEntry(BaseModel):
    type: str
    value: str
    reason: Optional[str] = ""
    duration_minutes: Optional[int] = None
