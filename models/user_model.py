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

