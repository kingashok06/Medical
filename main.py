from fastapi import FastAPI,HTTPException,Response,Request,Depends,File,APIRouter,UploadFile,Query
from routes.user_routes import user
from config.db import collection,EMAIL_CONFIG
from pydantic import BaseModel,EmailStr
from models.user_model import User,login,ChangePasswordRequest,UserProfile,ResetPasswordRequest,TeamCreate,TeamMember,AddMonitor
from bson import ObjectId
import jwt
from bson import ObjectId
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
import csv
from datetime import datetime, timedelta
from io import StringIO
from typing import List, Dict
from Bio import Entrez
import string
from jose import JWTError
import random
from config.db import collection
from bson import ObjectId
from fastapi.responses import JSONResponse  
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os,datetime,bcrypt
from datetime import datetime, timedelta

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
                raise HTTPException(status_code=401, detail="Invalid token or expired token.")
            return self.extract_user_id(credentials.credentials)
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        try:
            payload = jwt.decode(jwtoken, SECRET_KEY, algorithms=[ALGORITHM])
            return True
        except JWTError:
            return False

    def extract_user_id(self, jwtoken: str) -> dict:
        try:
            payload = jwt.decode(jwtoken, SECRET_KEY, algorithms=[ALGORITHM])
            return payload  # Return the entire payload, including user information
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token or expired token.")


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
async def register_user(user: User):
    # Check if the user already exists based on email, username, or contact number
    existing_user = collection.users.find_one({"$or": [{"email": user.email}, {"username": user.username}, {"contact": user.contact}]})
    if existing_user:
        if existing_user["username"] == user.username:
             raise HTTPException(status_code=400, detail="Username already exists")
        elif existing_user["email"] == user.email:
             raise HTTPException(status_code=400, detail="Email already exists")
        elif existing_user["contact"] == user.contact:
             raise HTTPException(status_code=400, detail="Contact number already exists")
        
     
    
    def validate_contact(contact):
        return len(str(contact)) == 10 
    
    if not validate_contact(user.contact):
        error_msg = "Invalid contact number. Contact number should have exactly 10 digits."
        raise HTTPException(status_code=400, detail=error_msg)

    confirmation_token = str(ObjectId())
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    user_data = {
        "username": user.username,
        "contact": user.contact,
        "email": user.email,
        "password": hashed_password.decode("utf-8"),
    }

    # Insert the user data into the database
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
    
    # Check if the provided password matches the hashed password in the database
    hashed_stored_password = existing_user["password"].encode("utf-8")
    hashed_input_password = bcrypt.hashpw(password.encode("utf-8"), hashed_stored_password)
    
    if hashed_stored_password != hashed_input_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id = str(existing_user["_id"])

    # Include the user_id in the payload
    payload = {
        "username": username,
        "_id": user_id,  # Include the user's _id in the payload
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }

    # return token_response(jwt_token)
    jwt_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return token_response(jwt_token)



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




# @app.get('/profile/{username}', response_model=UserProfile)
# async def get_user_profile(username: str):
#     user_data = collection.users.find_one({"username": username})
#     if user_data:
#         return UserProfile(
#             username=user_data['username'],
#             email=user_data['email'],
#         )
#     else:
#         raise HTTPException(status_code=404, detail="User not found")
#     existing_user = collection.users.find_one({"username": current_user})
#     if not existing_user:
#         raise HTTPException(status_code=404, detail="User not found")
    
#     stored_password = existing_user['password']
    
#     if not bcrypt.checkpw(request.current_password.encode("utf-8"), stored_password.encode("utf-8")):
#         raise HTTPException(status_code=401, detail="Invalid current password")
    
#     new_hashed_password = bcrypt.hashpw(request.new_password.encode("utf-8"), bcrypt.gensalt())
#     # Update the password in the database
#     collection.users.update_one({"username": current_user}, {"$set": {"password": new_hashed_password.decode("utf-8")}})
    
#     return {"message": "Password changed successfully"}

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
@app.put("/edit_profile")
async def edit_profile(
    username: str,
    user: User,  # Assuming User is your Pydantic model for user input
):
    # Check if the user exists
    existing_user = collection.find_one({"id": ObjectId(username)})
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
    Entrez.email = "uddhavsirsat12@gmail.com"
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
    
    csv_data = []
    for article in articles:
        title = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["ArticleTitle"] 
        abstract = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"].get("Abstract", {}).get("AbstractText", "")
        author_forename = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["AuthorList"][0]["ForeName"]
        pubmed_data = article["key"]["PubmedArticle"][0]["PubmedData"]
        pmid = article["key"]["PubmedArticle"][0]['MedlineCitation']['PMID']
        journal_title = article["key"]["PubmedArticle"][0]['MedlineCitation']['Article']['Journal']['Title']
        author_lastname = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["AuthorList"][0]["LastName"]
        csv_data.append((title, abstract, author_forename, pubmed_data, pmid, journal_title, author_lastname))
    
    # Define the CSV file path
    filename = "paracetamol1234.csv"
    
    # Write the CSV data to the file
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        
        # Write the header row
        writer.writerow(["Title", "Abstract", "Author Forename", "Pubmed Data", "PMID", "Journal Title", "Author Lastname"])
        
        # Write the data rows
        writer.writerows(csv_data)
    
    return {"message": "CSV file has been created successfully."}




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

@app.get("/search")
async def search_pubmed(filter_type: str = Query(..., title="Filter Type")):
    Entrez.email = "uddhavsirsat12@gmail.com"
    articles = []
    handle = Entrez.esearch(db="pubmed", term=filter_type, retmax=10)
    record = Entrez.read(handle)
    handle.close()

    for pubmed_id in record["IdList"]:
        article_handle = Entrez.efetch(
            db="pubmed", id=pubmed_id, retmode="xml")
        article_record = Entrez.read(article_handle)
        article_handle.close()
        articles.append({"key": article_record})

    csv_data = []
    for article in articles:
        article_data = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]
        pubmed_id = article_data["Journal"]["JournalIssue"]["PubDate"]["Year"]
        title = article_data["ArticleTitle"]

        abstract_list = article_data.get("Abstract", {}).get("AbstractText", [])
        abstract_string = abstract_list[0] if abstract_list else ""

        pub_date_dict = article_data["Journal"]["JournalIssue"]["PubDate"]
        year = int(pub_date_dict.get("Year", 1900))
        month = datetime.datetime.strptime(pub_date_dict.get("Month", "Jan"), "%b").month
        day = int(pub_date_dict.get("Day", 1))
        pub_date = datetime.datetime(year, month, day).strftime("%d-%m-%Y")
        
        upload_date_info = article["key"]["PubmedArticle"][0]["PubmedData"]["History"][0].get("PubMedPubDate", {})
        upload_year = int(upload_date_info.get("Year", 2023))
        upload_month = datetime.datetime.strptime(upload_date_info.get("Month", "Aug"), "%b").month
        upload_day = int(upload_date_info.get("Day", 17))
        upload_date = datetime.datetime(upload_year, upload_month, upload_day).strftime("%d-%m-%Y")
        
        pubmed_id = article_data["Journal"]["JournalIssue"]["PubDate"]["Year"]
        link = f"https://pubmed.ncbi.nlm.nih.gov/{pubmed_id}/"
        
        csv_data.append((pubmed_id, title, abstract_string, pub_date, upload_date, link))

    filename = "paracetamoljj.csv"
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["ID", "Title", "Abstract", "Date Published", "Date Uploaded", "Links"])
        writer.writerows(csv_data)

    return {"message": "CSV file has been created successfully."}

@app.get("/fetch_pubmed_data")
def fetch_pubmed_data(filter_type: str = Query(..., title="Filter Type")):
    articles = []
    
    handle = Entrez.esearch(db="pubmed", term=filter_type, retmax=10)
    record = Entrez.read(handle)
    handle.close()
    
    for pubmed_id in record["IdList"]:
        article_handle = Entrez.efetch(db="pubmed", id=pubmed_id, retmode="xml")
        article_record = Entrez.read(article_handle)
        article_handle.close()
        articles.append(article_record)
    
    processed_data = []
    for article in articles:
        try:
            pubmed_id = article['PubmedArticle'][0]['MedlineCitation']['PMID']
            title = article['PubmedArticle'][0]['MedlineCitation']['Article']['ArticleTitle']
            tags = []
            article_text = article['PubmedArticle'][0]['MedlineCitation']['Article']['ArticleTitle']  # Example: You can change this to the appropriate field
            if "suspected event" in article_text.lower():
                tags.append("suspected event")
            if "suspected adverse event" in article_text.lower():
                tags.append("suspected adverse event")
            if "suspected case" in article_text.lower():
                tags.append("suspected case")
            
            link = f"https://pubmed.ncbi.nlm.nih.gov/{pubmed_id}/"
            status = "In Queue"  # Set status as "In Queue"
            decision = "Valid"  # Set decision as "Valid"

            # tags = article.get('PubmedArticle', [{}])[0].get('MedlineCitation', {}).get('MeshHeadingList', [])
            # tags = [tag['DescriptorName'] for tag in tags] if tags else []
            # link = f"https://pubmed.ncbi.nlm.nih.gov/{pubmed_id}/"
            # status = "In Queue"  # Set status as "In Queue"
            # decision = "Valid"  # Set decision as "Valid"

            processed_data.append({
                "ID": pubmed_id,
                "Title": title,
                "Tags": tags,
                "Links": link,
                "Status": status,
                "Decision": decision
            })
        except KeyError:
            continue
    
    filename = "pubmed_data120.csv"
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Title", "Tags", "Links", "Status", "Decision"])
        
        for item in processed_data:
            writer.writerow([
                item["ID"], item["Title"], ", ".join(item["Tags"]),
                item["Links"], item["Status"], item["Decision"]
            ])
    
    return {"message": f"CSV file '{filename}' has been created successfully."}

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
        raise HTTPException(status_code=404, detail="CSV file not found")
    headers = {
    "file_download_status" : "Sucess"}

    return headers

# @app.get("/search")
# async def search_pubmed(filter_type: str = Query(..., title="Filter Type")):
#      Entrez.email = "uddhavsirsat12@gmail.com" 
#      articles = []
#      handle = Entrez.esearch(db="pubmed", term=filter_type, retmax=10)
#      record = Entrez.read(handle)
#      handle.close   
#      for pubmed_id in record["IdList"]:
#         article_handle = Entrez.efetch(
#             db="pubmed", id=pubmed_id, retmode="xml")
#         article_record = Entrez.read(article_handle)
#         article_handle.close()
#         articles.append({"key": article_record })
#      csv_data = []
#      for article in articles:
#         pubmed_id = article["key"]["PubmedArticle"][0]["MedlineCitation"]["PMID"]
#         title = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["ArticleTitle"]
#         abstract = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"].get(
#                  "Abstract", {}).get("AbstractText", "")
#         pub_date = article["key"]["PubmedArticle"][0]["MedlineCitation"]["Article"]["Journal"]["JournalIssue"]["PubDate"]
#         # upload_date = article["key"]["PubmedArticle"][0]["PubmedData"]["History"][0]["PubMedPubDate"]
#         link = f"https://pubmed.ncbi.nlm.nih.gov/{pubmed_id}/"
#         # abstract_summary = abstract[0] if abstract else ""
    
#         # csv_data.append((pubmed_id, title, abstract_summary, pub_date, link ))
#         csv_data.append((pubmed_id, title, abstract, pub_date, link )) 
#      filename = "medical.csv"
#      with open(filename, mode="w", newline="", encoding="utf-8") as file:
#         writer = csv.writer(file)
#         writer.writerow(
#             ["ID", "Title", "abstract", "Publication Date","Link"])
#         writer.writerows(csv_data)
#      return {"message": "CSV file has been created successfully."}
@app.post('/add_monitor')
async def add_monitor(
    monitor: AddMonitor,current_user: dict = Depends(JWTBearer())):
    if current_user.get("_id"):
        # Retrieve the user's _id from the JWT payload
        user_id = current_user.get("_id")
        username = current_user.get('username')

        if monitor.monitorname and monitor.excel_file:
            # Create a new monitor document
            monitor_data = {
                'username': username, # Associate the user's _id with the username
                'user_id': user_id,  # Associate the user's _id with the monitor data
                'monitorname': monitor.monitorname,
                'specialsituation': monitor.specialsituation,
                'description': monitor.description,
                'start_date': monitor.start_date,
                'end_date': monitor.end_date,
                'excel_file': monitor.excel_file
            }
            collection.insert_one(monitor_data)

            # Return a confirmation message
            confirmation_message = f"Monitor '{monitor.monitorname}' has been added successfully."
            return {'message': confirmation_message}

    return JSONResponse(content={"message": "User not authenticated"}, status_code=401)


@app.get('/user_monitors/{username}/{monitor_name}', response_model=list[dict])
async def get_user_monitor(
    username: str,
    monitor_name: str,
    current_user: dict = Depends(JWTBearer())
):
    # Check if the current user matches the username from the URL
    if current_user.get('username') == username:
        # Find all monitors for the provided username and monitor name
        monitors = collection.find({"username": username, "monitorname": monitor_name})

        # Convert the cursor to a list of dictionaries, excluding the ObjectId field
        monitor_list = [monitor for monitor in monitors]
        for monitor in monitor_list:
            monitor.pop('_id', None)  # Remove the ObjectId field

        if not monitor_list:
            raise HTTPException(status_code=404, detail=f"No monitors found for user: {username} and monitor name: {monitor_name}")

        return monitor_list
    else:
        raise HTTPException(status_code=403, detail="Access denied: You can only access your own data")


@app.put('/user_monitors/{username}/{monitorname}', response_model=dict)
async def update_user_monitor(
    username: str,
    monitorname: str,  # Monitor name from the URL
    monitor_data: AddMonitor,  # Use the same model for update data
    current_user: dict = Depends(JWTBearer())
):
    # Check if the current user matches the username from the URL
    if current_user.get('username') == username:
        # Create a filter to identify the monitor associated with the user and monitor name
        filter = {"username": username, "monitorname": monitorname}

        # Create an update query based on the provided monitor data
        update_query = {
            "$set": {
                'monitorname': monitor_data.monitorname,
                "specialsituation": monitor_data.specialsituation,
                "description": monitor_data.description,
                "start_date": monitor_data.start_date,
                "end_date": monitor_data.end_date,
                "excel_file": monitor_data.excel_file,
            }
        }

        # Perform the update operation in the database
        updated_monitor = collection.find_one_and_update(filter, update_query, return_document=True)

        if not updated_monitor:
            raise HTTPException(status_code=404, detail=f"No monitor found for user: {username} and monitor name: {monitorname}")

        # Remove the ObjectId field from the response
        updated_monitor.pop('_id', None)

        return updated_monitor
    else:
        raise HTTPException(status_code=403, detail="Access denied: You can only update your own data")


@app.delete('/user_monitors/{username}/{monitorname}', response_model=dict)
async def delete_user_monitor(
    username: str,
    monitorname: str,  # Monitor name from the URL
    current_user: dict = Depends(JWTBearer())
):
    # Check if the current user matches the username from the URL
    if current_user.get('username') == username:
        # Create a filter to identify the monitor associated with the user and monitor name
        filter = {"username": username, "monitorname": monitorname}

        # Perform the delete operation in the database
        deleted_monitor = collection.find_one_and_delete(filter)

        if not deleted_monitor:
            raise HTTPException(status_code=404, detail=f"No monitor found for user: {username} and monitor name: {monitorname}")

        # Remove the ObjectId field from the response
        deleted_monitor.pop('_id', None)

        return {"message": f"Monitor '{monitorname}' has been deleted successfully"}
    else:
        raise HTTPException(status_code=403, detail="Access denied: You can only delete your own data")
    

@app.post('/create_team')
async def create_team(team: TeamCreate, current_user: dict = Depends(JWTBearer())):
    if current_user.get("_id"):
        # Retrieve the user's _id from the JWT payload
        user_id = current_user.get("_id")
        username = current_user.get('username')

        if team.teamname and team.description:
            # Create a new team document
            team_data = {
                'teamname': team.teamname,
                'description': team.description,
                'creator_id': user_id,  # Associate the team creator's _id
                'members': [{"user_id": user_id, "username": username, "role": "admin"}]  # Initialize the members list with the creator as admin
            }
            team_id = collection.insert_one(team_data).inserted_id

            # Return a confirmation message
            confirmation_message = f"Team '{team.teamname}' has been created successfully."
            return {'message': confirmation_message, 'team_id': str(team_id)}

    return JSONResponse(content={"message": "User not authenticated"}, status_code=401)


@app.post('/add_member_to_team')
async def add_member_to_team(member: TeamMember):
    team_id = ObjectId(member.team_id)
    username = member.username  # Use the provided username
    # Debug: Print the username to see what's being used for the lookup
    print(f"Looking up user with username: {username}")
    # Check if the team exists
    team = collection.find_one({"_id": team_id})
    if not team:
        return {"error": "Team not found"}
    # Verify that the user exists by username from the users.users collection
    # Use the correct collection name here (users.users)
    user = collection.users.find_one({"username": username})
    if not user:
        # Debug: Print a message indicating that the user was not found
        print(f"User with username {username} not found in the users.users collection")

        return {"error": "User not found"}

    # Add the member to the team using the existing user ID
    collection.update_one(
        {"_id": team_id},
        {"$addToSet": {"members": {"user_id": str(user["_id"]), "username": user["username"]}}}
    )
    return {"message": f"{user['username']} added to the team."}

@app.delete('/remove_member_from_team')
async def remove_member_from_team(member: TeamMember, current_user: dict = Depends(JWTBearer())):
    if current_user.get("_id"):
        # Retrieve the user's _id from the JWT payload
        user_id = current_user.get("_id")
        username = current_user.get('username')

        team_id = ObjectId(member.team_id)
        username_to_remove = member.username  # The username of the user to remove

        # Check if the team exists
        team = collection.find_one({"_id": team_id})
        if not team:
            return {"error": "Team not found"}

        # Verify that the user exists by username from the users.users collection
        user = collection.users.find_one({"username": username})

        if not user:
            return {"error": "User not found"}

        # Check if the user trying to remove a member is an admin of the team
        is_admin = any(member['user_id'] == str(user['_id']) and member.get('role') == 'admin' for member in team['members'])

        if not is_admin:
            raise HTTPException(status_code=403, detail="Only admins can remove members from the team")

        # Find the user to remove by username
        user_to_remove = collection.users.find_one({"username": username_to_remove})

        if not user_to_remove:
            return {"error": "User to remove not found"}

        # Remove the user from the team
        collection.update_one(
            {"_id": team_id},
            {"$pull": {"members": {"user_id": str(user_to_remove["_id"])}}}
        )
        return {"message": f"{user_to_remove['username']} removed from the team."}

    return JSONResponse(content={"message": "User not authenticated"}, status_code=401)