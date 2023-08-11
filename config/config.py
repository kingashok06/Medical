from pymongo import MongoClient


# Database configuration.
database_connection = MongoClient("mongodb://localhost:27017")
database = database_connection.auth_database








