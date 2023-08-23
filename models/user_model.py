from pydantic import BaseModel,EmailStr
from typing import Optional
from datetime import date, datetime

class User(BaseModel):
    username: str
    contact: int 
    email : EmailStr
    password: str   
    # is_email_confirmed: bool = False
    # password: str = None
    confirmpassword: str = None
    photo: str = None

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
from bson import ObjectId

class TeamCreate(BaseModel):
    teamname: str
    description: str

class TeamMember(BaseModel):
    team_id: str
    username: str  # Use the existing username

class AddMonitor(BaseModel):
    monitorname: str
    specialsituation: str 
    description : str 
    start_date: datetime
    end_date: datetime
    excel_file: str
    # file: UploadFile