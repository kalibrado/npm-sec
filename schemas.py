from typing import Literal, Optional
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
    host: Optional[str] = None


class PolicyModeUpdate(BaseModel):
    host: Optional[str] = None
    mode: Literal["block", "observe"]


class ObservationIncidentStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]
