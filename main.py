from fastapi import FastAPI,HTTPException
from config.config import database,EMAIL_CONFIG
from routes.user_routes import user
from models.user_model import User
from models.login_model import  Login
from models.group_model import Group


import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson import ObjectId
import secrets



app = FastAPI()


app.include_router(user)



@app.post("/register")
async def userRegister(user: User):
    
    existing_user = database.register.find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        if existing_user["username"] == user.username:
             raise HTTPException(status_code=400, detail="Username already exists")
        elif existing_user["email"] == user.email:
             raise HTTPException(status_code=400, detail="Email already exists")
        
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password.decode("utf-8"),  # Store the hashed password in the database
        
    }
    
    result = database.register.insert_one(user_data)

    return {"message": "User registered successfully", "user_id": str(result.inserted_id)}



@app.post("/login")
async def userLogin(login:Login):

    username=login.username
    password=login.password

    exist_user=database.register.find_one({"username":username})
    
    if not exist_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if bcrypt.checkpw(password.encode("utf-8"),exist_user["password"].encode("utf-8")):
        
        return {"message": "Login successful", "user_id": str(exist_user["_id"])}

    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")



@app.post("/creategroup")
async def createGroup(group: Group):
    for member in group.add_members:
        exist_user = database.register.find_one({"username": member})
        
        if exist_user:

            add_member = {
                "group_name": group.group_name,
                "member_name": group.add_members
            }
            result = database.group.insert_one(add_member)

            subject="Added into the group"
            message=f'You Are Add In "{group.group_name}" Group'

            send_notification_email(exist_user["email"],subject,message)
        
        else:
            print(f"User '{member}' not found in register collection.")


    return {"message": "Group created successfully"}
 

def send_notification_email(to_email,subject,message):

    msg = MIMEMultipart()
    msg['From'] = EMAIL_CONFIG["SENDER_EMAIL"]
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    with smtplib.SMTP(EMAIL_CONFIG["SMTP_SERVER"], EMAIL_CONFIG["SMTP_PORT"]) as server:
        server.starttls()
        server.login(EMAIL_CONFIG["SENDER_EMAIL"], EMAIL_CONFIG["SENDER_PASSWORD"])  
        server.sendmail(EMAIL_CONFIG["SENDER_EMAIL"], to_email, msg.as_string())

