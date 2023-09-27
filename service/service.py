from fastapi_mail import ConnectionConfig
from decouple import config
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
import random
import redis
from config.db import SessionLocal
from models.user_model import UserInDB
from sqlalchemy import or_
from datetime import datetime, timedelta
from jose import jwt
import string
import secrets
from schemas.user_schema import UserDB
from fastapi import FastAPI
from schemas.auth import OTP


app = FastAPI()

conf = ConnectionConfig(
    MAIL_USERNAME=config('MAIL_USERNAME'),
    MAIL_PASSWORD=config("MAIL_PASSWORD"),
    MAIL_FROM=config("MAIL_FROM"),
    MAIL_PORT=config("MAIL_PORT"),
    MAIL_SERVER=config("MAIL_SERVER"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,

)


SECRET_KEY = config('SECRET_KEY')
ALGORITHM = config('ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES = config('ACCESS_TOKEN_EXPIRE_MINUTES', cast=int)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def startup_event():
    app.state.redis = redis.Redis(
        host='localhost',  # Replace with your Redis server host
        port=6379,         # Replace with your Redis server port
        db=0,              # Replace with the appropriate Redis database index
        decode_responses=True  # Ensure that responses are decoded to strings
    )

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Generate a random OTP
def generate_otp():
    return str(random.randint(100000, 999999))


def store_otp_in_redis(email: str, otp: str, expiration_seconds: int):
    # Set the OTP in Redis with a key based on the email
    key = f"otp:{email}"
    app.state.redis.setex(name=key, time=expiration_seconds, value=otp)


def verify_otp_in_redis(email: str, otp: str):
    # Get the stored OTP from Redis
    key = f"otp:{email}"
    stored_otp = app.state.redis.get(key)

    # Check if the stored OTP matches the input OTP
    return stored_otp == otp


def delete_otp_in_redis(email: str):
    # Delete the OTP key from Redis
    key = f"otp:{email}"
    app.state.redis.delete(key)


# Define a function to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Function to retrieve a user from the database by email
def get_user(db, email: str):
    user = db.query(UserDB).filter(UserDB.email == email).first()
    if user:
        return UserInDB(email=user.email, hashed_password=user.password)


# Function to authenticate a user by checking email and password
def authenticate_user(db, username: str, password: str):
    user = db.query(UserDB).filter(
        or_(UserDB.email == username, UserDB.name == username)).first()
    if user and verify_password(password, user.password):
        return user  # Include the user instance with is_verified status
    return None


# Function to create an access token with optional expiration time


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Token generation function
def generate_token(length=32):
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    return token

# Store the reset token and its expiration timestamp in the OTP table

def store_reset_token_in_database(db, email: str, reset_token: str):
    # Calculate the expiration timestamp, for example, 1 hour from now
    expiration_timestamp = datetime.utcnow() + timedelta(hours=1)

    # Create a new OTP record in the database
    otp_record = OTP(email=email, reset_token=reset_token,
                     expiration_timestamp=expiration_timestamp)
    db.add(otp_record)
    db.commit()

# Remove the OTP record after the token is used


def delete_reset_token_from_database(db, email: str):
    # Find and delete the OTP record associated with the given email
    otp_record = db.query(OTP).filter(OTP.email == email).first()
    if otp_record:
        db.delete(otp_record)
        db.commit()


