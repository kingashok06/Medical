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

