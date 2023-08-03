from fastapi import APIRouter, HTTPException
# from main import app
from config.config import db
import bcrypt

user = APIRouter()

@user.post("/login")
async def login_user(username: str, password: str):
    user = db.users.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    hashed_password = user["password"].encode("utf-8")
    if bcrypt.checkpw(password.encode("utf-8"), hashed_password):
        return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

# app.include_router(user, prefix="/user")
