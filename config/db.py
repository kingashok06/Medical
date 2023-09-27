<<<<<<< HEAD
from pymongo import MongoClient

db_connection = MongoClient("mongodb://localhost:27017")
db = db_connection.database_name
collection = db["collection_name"]



# client = MongoClient("mongodb://localhost:27017/")
# db = client["user_db"]
# collection = db["users"]



EMAIL_CONFIG = {
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 587,
    "SENDER_EMAIL": "rajps@infusionanalysts.com",
    "SENDER_PASSWORD": "xcscmpccrpjxkeaq",
}

=======

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from decouple import config
# Load environment variables from .env file
load_dotenv('.env')

DATABASE_URL = config('DATABASE_URL')


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
>>>>>>> 732d2d0 (Team_APIs)
