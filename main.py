from fastapi import FastAPI,HTTPException
from config.db import db
from routes.user_routes import user
from models.user_model import User
from models.login_model import  login
from models.group_model import RequestGroup


import bcrypt
import uuid
import smtplib
from email.mime.text import MIMEText
from bson import ObjectId
import secrets
app = FastAPI()


app.include_router(user)

@app.post("/register")
async def register_user(user: User):
    # Check if the user already exists based on email or username
    existing_user = db.register.find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        if existing_user["username"] == user.username:
             raise HTTPException(status_code=400, detail="Username already exists")
        elif existing_user["email"] == user.email:
             raise HTTPException(status_code=400, detail="Email already exists")
        
     
    # confirmation_token = str(ObjectId())
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password.decode("utf-8"),  # Store the hashed password in the database
        # "confirmation_token": confirmation_token
    }
    
    result = db.register.insert_one(user_data)
    
    print(result)
    # Create a link to the confirmation endpoint on your website
    # Put your login url
    # confirmation_link = f"https://www.google.com/?token={confirmation_token}"
    

 
    # Send the confirmation email
    # send_confirmation_email(user.email, confirmation_link)

    return {"message": "User registered successfully", "user_id": str(result.inserted_id)}
# "confirmation_token": confirmation_token


@app.post("/login")
async def login(login_user:login):

    username=login_user.username
    password=login_user.password

    exist_user=db.register.find_one({"username":username})
    
    if not exist_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if bcrypt.checkpw(password.encode("utf-8"),exist_user["password"].encode("utf-8")):
        
        return {"message": "Login successful", "user_id": str(exist_user["_id"])}

    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")



@app.post("/create_group")
async def create_group(group_data: RequestGroup):
    for member in group_data.add_members:
        exist_user = db.register.find_one({"username": member})
        if exist_user:
            add_member = {
                "group_name": group_data.group_name,
                "member_name": member
            }
            result = db.group.insert_one(add_member)
            print(result.inserted_id)  # Print the inserted document's ID
        else:
            print(f"User '{member}' not found in register collection.")
    return {"message": "Group created successfully"}