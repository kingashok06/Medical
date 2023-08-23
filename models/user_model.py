from pydantic import BaseModel,EmailStr,constr
from datetime import date, datetime
from fastapi import UploadFile


class User(BaseModel):
    username: str
    contact: int 
    email : EmailStr
    password: constr(min_length=8)
    # password: str   
    # is_email_confirmed: bool = False


class login(BaseModel):
    username:str
    password:str
   
class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: constr(min_length=8)

class UserProfile(BaseModel):
    username: str
    email : str


class AddMonitor(BaseModel):
    monitorname: str
    specialsituation: str 
    description : str 
    start_date: datetime
    end_date: datetime
    excel_file: str
    # file: UploadFile

class TeamCreate(BaseModel):
    teamname: str
    description: str

class TeamMember(BaseModel):
    team_id: str
    username: str  # Use the existing username




