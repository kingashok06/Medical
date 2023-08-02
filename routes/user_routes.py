from fastapi import APIRouter,HTTPException
from models.user_model import User
# from schemas.user_schema import users_serializer
from bson import ObjectId
from config.db import collection
# from .custom_exceptions import UserAlreadyExists, EmailAlreadyExists
import bcrypt

user = APIRouter()


@user.post("/register/")
async def register_user(user: User):
    # Check if the user already exists based on email or username
    existing_user = collection.users.find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    if existing_user:
        if existing_user["username"] == user.username:
             raise HTTPException(status_code=400, detail="Username already exists")
        elif existing_user["email"] == user.email:
             raise HTTPException(status_code=400, detail="Email already exists")

    # Hash the password before storing it in the database
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password.decode("utf-8"),  # Store the hashed password in the database
    }
    result = collection.users.insert_one(user_data)

    return {"message": "User registered successfully", "user_id": str(result.inserted_id)}





