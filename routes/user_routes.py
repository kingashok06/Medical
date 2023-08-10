from fastapi import APIRouter,HTTPException
from models.user_model import User
# from schemas.user_schema import users_serializer
from bson import ObjectId
from config.db import collection
import bcrypt
from fastapi import FastAPI
from main import routers

app = FastAPI()

@app.get("/")
async def home():
    return {"message": "Hello World"}
app.include_router(routers)


user = APIRouter()




