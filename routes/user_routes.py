from fastapi import APIRouter,HTTPException
from models.user_model import User
# from schemas.user_schema import users_serializer
from bson import ObjectId
from config.db import db
# from .custom_exceptions import UserAlreadyExists, EmailAlreadyExists
import bcrypt

user = APIRouter()




