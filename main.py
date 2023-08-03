from fastapi import FastAPI,HTTPException
from routes.user_routes import user
from models.user_model import User
from config.db import collection,EMAIL_CONFIG
import bcrypt
import uuid
import smtplib
from email.mime.text import MIMEText
from bson import ObjectId
import secrets
app = FastAPI()


app.include_router(user)

@app.post("/register/")
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

    return {"message": "User registered successfully", "user_id": str(result.inserted_id),"confirmation_token": confirmation_token}



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