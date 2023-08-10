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


import string
import random
from random import randint
from models.user_model import ProfileUpdate,User,PasswordResetRequest,login
from fastapi import UploadFile,File,APIRouter,HTTPException
# from Model.model import User, profileUpdate, login
# from Model.model import ResetPasswordRequest
from config.db import collection
from bson import ObjectId
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

routers = APIRouter()


class ResetPasswordRequest(BaseModel):
 email: str

@routers.post("/register")
async def register_user(user:User):
 new_user = {
  "username":user.username,
  "email":user.email,
  "password":user.password,
  "confirmpassword":user.password,
  "photo": b"d`efault_image"
 }
 
 collection.insert_one(new_user)
 return{"message":"sucessfully"}


#  Endpoint to edit user profile using PUT method
@routers.put("/edit_profile/{user_id}")
async def edit_profile(
    user_id: str,
    user: User,  # Assuming User is your Pydantic model for user input
):
    # Check if the user exists
    existing_user = collection.find_one({"_id": ObjectId(user_id)})
    if not existing_user:
        return JSONResponse(content={"error": "User not found"}, status_code=404)

    # Update username and email
    update_data = {
        "username": user.username,
        "email": user.email,
    }
    # Update photo path if it's provided in the JSON body
    if user.photo:
        photo_path = user.photo  # Assuming the user.photo field contains the full path
        update_data['photo_path'] = photo_path

    # Update the user data in MongoDB
    collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})

    return JSONResponse(content={"message": "Profile updated successfully"})



@routers.post("/login/User")
async def user_login(login_data: login):
 user = collection.find_one({"username": login_data.username})
 print(user)
 if user is None or user["password"] != login_data.password:
    raise HTTPException(status_code=401, detail="Invalid credentials")
 return {"message": "Login successful"}


reset_tokens = {}


def generate_random_string(length):
   letters_and_digits = string.ascii_letters + string.digits
   return ''.join(random.choice(letters_and_digits) for _ in range(length))

@routers.post("/forgot-password/user")
# @app.post("/forgot-password")
async def forgot_password(request: ResetPasswordRequest):
 user = collection.find_one({"email": request.email})
 if user:
    reset_token = generate_random_string(32)
    reset_tokens[reset_token] = user
    print(request.email,reset_token)
    send_reset_email(request.email, reset_token)
    return {"message": "Password reset link sent"}
 raise HTTPException(status_code=404, detail="User not found")


     

def send_reset_email(email, reset_token):
    # Configure your SMTP settings
    smtp_host = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "uddhavsirsat12@gmail.com"
    app_password = "weycahucciwloyei"
    sender_email = "uddhavsirsat12@gmail.com"
    subject = "Password Reset"
    
    # Corrected URL format
    reset_link = f"http://127.0.0.1:8000/reset-password/{reset_token}"
    
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["Subject"] = subject
    
    body = f"Click the following link to reset your password: {reset_link}"
    message.attach(MIMEText(body, "plain"))
    
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, app_password)
            server.sendmail(sender_email, email, message.as_string())
            print("Email sent successfully")
            return True
    except Exception as e:
        print("Error sending email:", e)



import csv
from io import StringIO
from typing import List, Dict
from fastapi import FastAPI, Response,HTTPException,UploadFile,File
from pydantic import BaseModel
import os
from Bio import Entrez

# Initialize the Entrez email (required by PubMed API)
Entrez.email = "uddhavsirsat12@email.com"

# Create a FastAPI instance
app = FastAPI()

# Define the response model for the article["key"]["PubmedArticle"][0]["MedlineCitation"]
class ArticleResponseModel(BaseModel):
    key: Dict

@app.get("/search/{query}")
async def search_pubmed(query: str):
    articles = []
    
    # Perform the PubMed search
    handle = Entrez.esearch(db="pubmed", term=query, retmax=10)
    record = Entrez.read(handle)
    handle.close()
    
    for pubmed_id in record["IdList"]:
        # Fetch details of each article using PubMed ID
        article_handle = Entrez.efetch(db="pubmed", id=pubmed_id, retmode="xml")
        article_record = Entrez.read(article_handle)
        article_handle.close()
        articles.append({"key": article_record})
        # print(articles)
    
    for article in articles:
        csv_data = []
        title = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["ArticleTitle"] 
        abstract = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"].get("Abstract", {}).get("AbstractText", "")
        AuthorList = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["AuthorList"][0]["ForeName"]
        csv_data.append((title, abstract, AuthorList))
        print(csv_data)
    # Define the CSV file path
        filename = "output.csv"
        print(filename)
    # Write the CSV data to the file
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
    # Write the header row
            writer.writerow(["Title", "Abstract", "AuthorList"])
                # Write the data rows
            writer.writerows(csv_data)
        print("CSV file has been created successfully.")

@app.get("/all_data/{query}")
async def search_pubmed(query: str):
    articles = []
    
    # Perform the PubMed search
    handle = Entrez.esearch(db="pubmed", term=query, retmax=10)
    record = Entrez.read(handle)
    handle.close()
    
    for pubmed_id in record["IdList"]:
        # Fetch details of each article using PubMed ID
        article_handle = Entrez.efetch(db="pubmed", id=pubmed_id, retmode="xml")
        article_record = Entrez.read(article_handle)
        article_handle.close()
        articles.append({"key": article_record})
        # print(articles)
    
    for article in articles:
        csv_data = []
        title = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["ArticleTitle"] 
        abstract = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"].get("Abstract", {}).get("AbstractText", "")
        AuthorList = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["AuthorList"][0]["ForeName"]
        PubmedData = article["key"]["PubmedArticle"][0]["PubmedData"]
        pmid = article["key"]["PubmedArticle"][0]['MedlineCitation']['PMID']
        journal_title = article["key"]["PubmedArticle"][0]['MedlineCitation']['Article']['Journal']['Title']
        AuthorList_1 = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["AuthorList"][0]["LastName"]
        csv_data.append((title, abstract, AuthorList, PubmedData,pmid,journal_title,AuthorList_1))
        print(csv_data)
    # Define the CSV file path
        filename = "paracetamol.csv"
        print(filename)
    # Write the CSV data to the file
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
    # Write the header row
            writer.writerow(["Title", "Abstract", "AuthorList", "PubmedData","pmid", "journal_title", "AuthorList_1"])
                # Write the data rows
            writer.writerows(csv_data)
        print("CSV file has been created successfully.")

@app.get("/download-csv/{csv_file_path}")
async def download_csv(csv_file_path: str):
    # Define the folder path where the CSV file is located
    folder_path = "/home/dev14/Downloads/Medapp/"
    download_path = "/home/dev14/Downloads"
    # Define the CSV file path
    csv_file_path = os.path.join(folder_path, f"{csv_file_path}")
    print("CSV file path:", csv_file_path)
    # Check if the CSV file exists
    if os.path.exists(csv_file_path):
        os.system(f"cp {csv_file_path} {download_path}")
    else:
        raise HTTPException(status_code=404, detail="CSV file not found")
    headers = {
    "file_download_status" : "Sucess"}

    return headers
