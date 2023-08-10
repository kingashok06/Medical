from pydantic import BaseModel,EmailStr
from typing import Optional

class User(BaseModel):
    username: str
    email : EmailStr
    password: str
    confirmpassword: str
    is_email_confirmed: bool = False


# Profile update model with an optional photo field
class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    photo: Optional[bytes] = None

class login(BaseModel):
    username:str
    password:str

class PasswordResetRequest(BaseModel):
        username: str  # Corrected from email: str
