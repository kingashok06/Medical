# from pymongo import MongoClient

# db_connection = MongoClient("mongodb://localhost:27017")
# db = db_connection.database_name
# collection = db["collection_name"]
from dotenv import load_dotenv

import os
from pymongo import MongoClient
load_dotenv()
db_connection = MongoClient("mongodb://localhost:27017")
db = db_connection["data"]
collection = db["login"]


# client = MongoClient("mongodb://localhost:27017/")
# db = client["user_db"]
# collection = db["users"]


EMAIL_CONFIG = {
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 587,
    "smtp_username":"uddhavsirsat12@gmail.com",
    "SENDER_EMAIL": "uddhavsirsat12@gmail.com",
    "SENDER_PASSWORD": "cedayvubegjkgwst",
}

