from fastapi import FastAPI,HTTPException,Response,Request,Depends,Query
from routes.user_routes import user
from config.db import collection,EMAIL_CONFIG
from pydantic import ValidationError
from models.user_model import User,login,ChangePasswordRequest,UserProfile,AddMonitor
import smtplib
from email.mime.text import MIMEText
from bson import ObjectId
import jwt
import bcrypt
from bson import ObjectId
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict
import time
from fastapi.responses import JSONResponse,RedirectResponse
from starlette.requests import Request
from datetime import datetime, timedelta
from jose import JWTError


app = FastAPI()


app.include_router(user)


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
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
