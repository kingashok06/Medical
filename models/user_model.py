from pydantic import BaseModel,EmailStr

class User(BaseModel):
    id:str
    username: str
    email : EmailStr
    password: str
    confirmpassword: str
    is_email_confirmed: bool = False



