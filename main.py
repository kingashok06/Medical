from fastapi import FastAPI,HTTPException,Response,Request,Depends,File,APIRouter,UploadFile
from routes.user_routes import user
from config.db import collection,EMAIL_CONFIG
from pydantic import BaseModel,EmailStr
from models.user_model import User,login,ChangePasswordRequest,UserProfile,ResetPasswordRequest
from bson import ObjectId
import jwt
from bson import ObjectId
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
import csv
from io import StringIO
from typing import List, Dict
from pydantic import BaseModel
from Bio import Entrez
import string
import random
from config.db import collection
from bson import ObjectId
from fastapi.responses import JSONResponse  
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import bcrypt
from dotenv import load_dotenv
import os
routers = APIRouter()
load_dotenv()


reset_token = str(ObjectId())
confirmation_link = f"http://127.0.0.1:8000/reset_password/?token={reset_token}"

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

#Endpoint to edit user profile using PUT method
@app.put("/edit_profile/{user_id}")
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
            writer.writenew_Confirm_Passwordrow(["Title", "Abstract", "AuthorList", "PubmedData","pmid", "journal_title", "AuthorList_1"])
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

# reset_tokens = {}

# def generate_random_string(length):
#    letters_and_digits = string.ascii_letters + string.digits
#    return ''.join(random.choice(letters_and_digits) for _ in range(length))



def send_reset_email(email: str, confirmation_link: str):
    # confirmation_link = f"http://127.0.0.1:8000/login/?token={confirmation_token}"
    subject = "Password resetlink"
    body = f"Hello,\n\nPassword reset link.\n\nPlease click on the link below to reset your password address:{confirmation_link}"

    msg = MIMEText(body)
    msg["From"] = EMAIL_CONFIG["SENDER_EMAIL"]
    msg["To"] = email
    msg["Subject"] = subject

    # Connect to the SMTP server and send the email
    with smtplib.SMTP(EMAIL_CONFIG["SMTP_SERVER"], EMAIL_CONFIG["SMTP_PORT"]) as server:
        server.starttls()
        server.login(EMAIL_CONFIG["SENDER_EMAIL"], EMAIL_CONFIG["SENDER_PASSWORD"])
        server.sendmail(EMAIL_CONFIG["SENDER_EMAIL"], email, msg.as_string())

@app.post('/forgot_password')
async def forgot_password(email: str):
    existing_user = collection.users.find_one({'email': email})
    if not existing_user:
        raise HTTPException(status_code=401, detail='user not found')
    
    send_reset_email(email,confirmation_link)


    return {'message' : 'Password reset link sent to email'}


@app.put('/reset_password', dependencies=[Depends(JWTBearer())])
async def password(reset_data: ResetPasswordRequest):
    existing_user = collection.users.find_one({'email': reset_data.email})
    if not existing_user:
        raise HTTPException(status_code=401, detail='User not found')
    # new_hashed_password = bcrypt.hashpw(reset_data.new_password.encode("utf-8"), bcrypt.gensalt())
    new_hashed_password = bcrypt.hashpw(reset_data.new_password.encode("utf-8"), bcrypt.gensalt())
    a= reset_data.new_password
    print("new pass:-",a)
    b= reset_data.confirmpassword
    print("confirm pass:-",b)
    # Update the password and reset token in the database
    new_Confirm_Password = bcrypt.hashpw(reset_data.confirmpassword.encode("utf-8"), bcrypt.gensalt())
    if reset_data.new_password==reset_data.confirmpassword:
        print("cjsdgdgfefgrughtitrh")
#     # Update the password in the database
        collection.users.update_one( {"email": reset_data.email}, {"$set": {"password": new_hashed_password.decode("utf-8")}})
        print(collection)
        return {"message": "Password changed successfully"}
    else:
        return{"message":"Password Doen't Mached!"}

    
