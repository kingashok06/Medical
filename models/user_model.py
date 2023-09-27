<<<<<<< HEAD
from pydantic import BaseModel,EmailStr

class User(BaseModel):
    username: str
    email : EmailStr
    password: str
    confirmpassword: str
    is_email_confirmed: bool = False


class login(BaseModel):
    username:str
    password:str
   
class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class UserProfile(BaseModel):
    username: str
    email : str

=======
from pydantic import BaseModel, EmailStr, constr
from datetime import datetime
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String,DateTime
from typing import List

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: constr(min_length=8)


class UserResponse(BaseModel):
    id: int
    name: str
    email: str


class UserLogin(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class User(BaseModel):
    email: str
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str






#################
class TeamCreate(BaseModel):
    teamname: str
    description: str
    team_link:str=None
    created_at:datetime
    updated_at:datetime
    deleted_status:bool=False
    

    class Config:
        orm_mode = True



class TeamMember(BaseModel):
    team_id:int
    members:List[str]



class AddMember(BaseModel):
    member:str

    class Config:
        orm_mode = True



# class Demo(BaseModel):
#     name:str
#     # json_data:dict
#     city:str

#     class Config:
#         orm_mode = True
>>>>>>> 732d2d0 (Team_APIs)
