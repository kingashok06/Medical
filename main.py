from fastapi import FastAPI,HTTPException,Response,Request,Depends  
from routes.user_routes import user
from config.db import collection,EMAIL_CONFIG
from pydantic import BaseModel,EmailStr
from models.user_model import User,login,ChangePasswordRequest,UserProfile
import bcrypt
import smtplib
from email.mime.text import MIMEText
from bson import ObjectId
from fastapi import FastAPI, HTTPException
import bcrypt
import jwt
import smtplib
from email.mime.text import MIMEText
from fastapi import FastAPI,HTTPException
import bcrypt
import smtplib
from bson import ObjectId
from pydantic import BaseModel,EmailStr,Field
import os
#The goal of this file is to check whether the reques tis authorized or not [ verification of the proteced route]
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict
import time



app = FastAPI()


app.include_router(user)


SECRET_KEY = os.urandom(32) 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = decodeJWT(jwtoken)
        except:
            payload = None
        if payload:
            isTokenValid = True
        return isTokenValid
    








def token_response(token: str):
    return {
        "access_token": token
    }

# function used for signing the JWT string
def signJWT(user_id: str) -> Dict[str, str]:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 600
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return token_response(token)


def decodeJWT(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {}


def check_user(data: login):
    for user in User:
        if user.email == data.email and user.password == data.password:
            return True
    return False



@app.post("/register/")
# @app.post("/user/signup", tags=["user"])
async def register_user(user: User):
    # Check if the user already exists based on email or username
    existing_user = collection.users.find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        if existing_user["username"] == user.username:
             raise HTTPException(status_code=400, detail="Username already exists")
        elif existing_user["email"] == user.email:
             raise HTTPException(status_code=400, detail="Email already exists")
        
    
    
  
    confirmation_token = str(ObjectId())
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password.decode("utf-8"),  # Store the hashed password in the database
        "confirmation_token": confirmation_token
    }
    result = collection.users.insert_one(user_data)

    # Create a link to the confirmation endpoint on your website
    # Put your login url
    confirmation_link = f"https://www.google.com/?token={confirmation_token}"
    

 
    # Send the confirmation email
    send_confirmation_email(user.email, confirmation_link)

    return {"message": "User registered successfully", "user_id": str(result.inserted_id)} #"JWT_TOKEN": signJWT(user.email)



def send_confirmation_email(to_email: str, confirmation_link: str):
    subject = "Account Confirmation"
    body = f"Hello,\n\nThank you for registering with our service. Your account has been successfully created.\n\nPlease click on the link below to confirm your email address:\n\n{confirmation_link}"

    msg = MIMEText(body)
    msg["From"] = EMAIL_CONFIG["SENDER_EMAIL"]
    msg["To"] = to_email
    msg["Subject"] = subject

    # Connect to the SMTP server and send the email
    with smtplib.SMTP(EMAIL_CONFIG["SMTP_SERVER"], EMAIL_CONFIG["SMTP_PORT"]) as server:
        server.starttls()
        server.login(EMAIL_CONFIG["SENDER_EMAIL"], EMAIL_CONFIG["SENDER_PASSWORD"])
        server.sendmail(EMAIL_CONFIG["SENDER_EMAIL"], to_email, msg.as_string())







@app.post("/login/") #dependencies=[Depends(JWTBearer())]
# async def login_user(login_data: login):
async def login_user(login_data: login):

    username = login_data.username
    password = login_data.password

    # Check if the user exists based on the provided username
    existing_user = collection.users.find_one({"username": username})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    print("Stored Hashed Password:", existing_user["password"])
    
    # Check if the provided password matches the hashed password in the database
    hashed_stored_password = existing_user["password"].encode("utf-8")
    hashed_input_password = bcrypt.hashpw(password.encode("utf-8"), hashed_stored_password)
    
    if hashed_stored_password != hashed_input_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    


     # Generate a JWT token
    jwt_token = signJWT(username)
  

    
    
  
    # Return some user information or a token to indicate successful login
    return {"message": "Login successful", "user_id": str(existing_user["_id"]),"JWT_TOKEN": jwt_token}
    # return {"JWT_TOKEN": signJWT(login.email)}






@app.put('/change_password/', dependencies=[Depends(JWTBearer())]) #
async def change_password(request: ChangePasswordRequest, current_user: str):
    existing_user = collection.users.find_one({"username": current_user})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    stored_password = existing_user['password']
    
    if not bcrypt.checkpw(request.current_password.encode("utf-8"), stored_password.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid current password")
    
    new_hashed_password = bcrypt.hashpw(request.new_password.encode("utf-8"), bcrypt.gensalt())
    # Update the password in the database
    collection.users.update_one({"username": current_user}, {"$set": {"password": new_hashed_password.decode("utf-8")}})
    
    return {"message": "Password changed successfully"}




@app.get('/profile/{username}', response_model=UserProfile)
async def get_user_profile(username: str):
    user_data = collection.users.find_one({"username": username})
    if user_data:
        return UserProfile(
            username=user_data['username'],
            email=user_data['email'],
        )
    else:
        raise HTTPException(status_code=404, detail="User not found")



