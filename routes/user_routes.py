from fastapi import APIRouter,HTTPException
from models.user_model import User
from bson import ObjectId
from config.db import collection
import bcrypt

user = APIRouter()




