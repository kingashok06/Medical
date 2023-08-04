from pymongo import MongoClient

db_connection = MongoClient("mongodb://localhost:27017")
db = db_connection.auth_database




# EMAIL_CONFIG = {
#     "SMTP_SERVER": "smtp.gmail.com",
#     "SMTP_PORT": 587,
#     "SENDER_EMAIL": "",
#     "SENDER_PASSWORD": "xcscmpccrpjxkeaq",
# }

