from pydantic import BaseModel,EmailStr
from typing import Optional


class User(BaseModel):
    username: str
    email : EmailStr
    password: str
    confirmpassword: str
    is_email_confirmed: bool = False
    # password: str = None
    # confirmpassword: str = None
    # photo: str = None

class login(BaseModel):
    username:str
    password:str
   
class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class UserProfile(BaseModel):
    username: str
    email : str

class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    photo: Optional[bytes] = None

class ResetPasswordRequest(BaseModel):
    email: str
    # token: str
    new_password: str
    confirmpassword: str

# class ResetPasswordRequest(BaseModel):
#  email: str