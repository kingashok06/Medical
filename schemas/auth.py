from sqlalchemy import Column, Integer, String, DateTime, func
from config.db import Base,engine


class OTP(Base):
    __tablename__ = "token"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    reset_token = Column(String)
    expiration_timestamp = Column(DateTime)


Base.metadata.create_all(bind=engine)