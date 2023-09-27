from sqlalchemy import Column, Integer, String, Boolean, DateTime, TIMESTAMP, func,ARRAY,ForeignKey,JSON
from config.db import Base, engine
from sqlalchemy.orm import relationship


class UserDB(Base):
    __tablename__ = "register"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    contactno = Column(String(length=10), nullable=True)
    profile_picture_filename = Column(String, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), onupdate=func.now())
    is_verified = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

class TeamCreateBase(Base):
    __tablename__ = "team"

    id = Column(Integer, primary_key=True, index=True)
    teamname = Column(String)
    description = Column(String)
    team_link = Column(String, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), onupdate=func.now())
    deleted_status = Column(Boolean,default=False)

    members=relationship("AddMemberBase",back_populates="team")

class AddMemberBase(Base):
    __tablename__ = "member"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("team.id"))

    member = Column(String)
    token= Column(String,nullable=True)
    joined = Column(Boolean,default=False)
    role=Column(String,nullable=True)

    # Define a many-to-one relationship to TeamCreateBase model
    team = relationship("TeamCreateBase", back_populates="members")

Base.metadata.create_all(bind=engine)



# class DemoBase(Base):

#     __tablename__ = "demo"

#     id=Column(Integer, primary_key=True, index=True)
#     name=Column(String)
#     json_data=Column(JSON)

# Base.metadata.create_all(bind=engine)



class DemoBase(Base):

    __tablename__ = "demo"

    id=Column(Integer, primary_key=True, index=True)
    name=Column(String)
    city=Column(String)

Base.metadata.create_all(bind=engine)







