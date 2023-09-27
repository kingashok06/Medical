import re
from config.db import *
from redis import Redis
from service.service import *
from schemas.auth import OTP
from sqlalchemy import or_
from typing import Annotated
from pydantic import EmailStr
from dotenv import load_dotenv
from jose import JWTError, jwt

from schemas.user_schema import UserDB,TeamCreateBase,AddMemberBase,DemoBase
from passlib.hash import bcrypt
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, status,UploadFile
from fastapi_mail import FastMail, MessageSchema, MessageType
from fastapi.security import OAuth2PasswordRequestForm

from models.user_model import UserCreate, UserResponse, UserInDB, User,TeamCreate,TeamMember,AddMember    #,Demo
from models.auth import Token,TokenData,ChangePasswordRequest, ResetPasswordRequest, ForgotPasswordRequest

# Load environment variables from .env file
load_dotenv('.env')


app = FastAPI()


fast_mail = FastMail(conf)

Base.metadata.create_all(bind=engine)

# @app.on_event('shutdown')


async def shutdown_event():
    app.state.redis.close()


# Endpoint to verify OTP
async def verify_otp_endpoint(email: EmailStr, otp: str, db: Session = Depends(get_db)):
    # Check if the OTP exists in Redis
    if verify_otp_in_redis(email, otp):
        # OTP is valid, remove it from Redis
        delete_otp_in_redis(email)

        # Update user verification status in the database
        user = db.query(UserDB).filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.commit()

        return {"message": "OTP verification has been successful"}

    raise HTTPException(status_code=400, detail="OTP verification failed")


# Endpoint for user registration


async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        # Check if the user already exists based on email or name
        existing_user = db.query(UserDB).filter(
            or_(UserDB.email == user.email, UserDB.name == user.name)).first()

        if existing_user:
            raise HTTPException(
                status_code=400, detail="Email or Username already exists")

        # Validate user password complexity
        pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$"
        if not re.match(pattern, user.password):
            raise HTTPException(
                status_code=400, detail="Password must meet complexity requirements")

        # Hash the password
        hashed_password = hash_password(user.password)

        # Prepare user data for database insertion
        user_data = UserDB(email=user.email, name=user.name,
                           password=hashed_password)

        # Check if an OTP already exists for this email
        existing_otp = db.query(OTP).filter(OTP.email == user.email).first()

        if not existing_otp:
            otp = generate_otp()

            # Store OTP in Redis
            # Adjust expiration_seconds as needed
            store_otp_in_redis(user.email, otp, expiration_seconds=600)

            # Send OTP via email
            message = MessageSchema(
                subject="OTP Verification",
                recipients=[user.email],
                body=f"Your OTP for email verification is: {otp}",
                subtype=MessageType.html
            )

            try:
                await fast_mail.send_message(message)
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        # Insert the user data into the database
        db.add(user_data)
        db.commit()
        db.refresh(user_data)

        # Close the session
        db.close()

        # Return a response model with the registered user's data
        return UserResponse(id=user_data.id, email=user_data.email, name=user_data.name)
    except IntegrityError as e:
        # Handle the case where the email or username already exists in the database
        raise HTTPException(
            status_code=400, detail="Email or Username already exists")

# Function to get the current user from a JWT token


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(SessionLocal(), email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Endpoint for user login and generating an access token
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(
        SessionLocal(), form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is verified
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='User is not verified. Please verify your account.', headers={'WWW.Authenticate': 'Bearer'})

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# FastAPI route for changing the password with confirmation
async def change_password(
    request: ChangePasswordRequest,
    current_user: UserInDB = Depends(
        get_current_active_user),  # Add authorization here
    db: Session = Depends(get_db)
):
    try:
        # The user is authorized, and you have access to current_user

        # Check if the user exists in the database
        user = db.query(UserDB).filter(
            UserDB.email == current_user.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify the provided current_password against the stored hashed password
        if not bcrypt.verify(request.current_password, user.password):
            raise HTTPException(
                status_code=401, detail="Invalid current password")

        # Check if the new password meets complexity requirements
        pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$"
        if not re.match(pattern, request.new_password):
            raise HTTPException(
                status_code=400, detail="New password must be at least 8 characters long and contain at least one letter, one digit, and one special character.")

        # Check if the new password matches the confirmation password
        if request.new_password != request.confirm_password:
            raise HTTPException(
                status_code=400, detail="New password and confirmation password do not match")

        # Hash the new password
        hashed_password = bcrypt.hash(request.new_password)

        # Update the password in the database
        user.password = hashed_password
        db.commit()

        return {"message": "Password changed successfully"}

    except Exception as e:
        # Handle database or other exceptions appropriately
        return {"error": str(e)}


async def forgot_password(email: EmailStr, db: Session = Depends(get_db)):
    try:
        # Check if a user with the provided email exists
        user = db.query(UserDB).filter(UserDB.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail='User not found')

        # Check if an OTP record already exists for the given email
        existing_otp = db.query(OTP).filter(OTP.email == email).first()
        if existing_otp:
            # Delete the existing OTP record
            db.delete(existing_otp)
            db.commit()

        # Generate a password reset token
        reset_token = generate_token()

        # Store the reset token in the database
        store_reset_token_in_database(db, email, reset_token)

        # Build the password reset link
        # Replace with your actual reset link
        reset_link = f'https://example.com/reset_password?token={reset_token}'

        # Send the password reset email with the reset token
        subject = 'Password Reset Link'
        body = f'Click the following link to reset your password: {reset_link}'

        message = MessageSchema(
            subject=subject,
            recipients=[email],
            body=body,
            subtype='html'
        )

        await fast_mail.send_message(message)

        # Return a response indicating that the email has been sent
        return {'message': 'Reset link has been sent successfully to your email'}

    except Exception as e:
        return {'error': str(e)}


async def reset_password(request: ResetPasswordRequest,  db: Session = Depends(get_db)):
    try:
        email = request.email  # Extract the email from the request

        user = db.query(UserDB).filter(UserDB.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail='User not found')

         # Check if the new password meets complexity requirements
        pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$"
        if not re.match(pattern, request.new_password):
            raise HTTPException(
                status_code=400, detail="New password must be at least 8 characters long and contain at least one letter, one digit, and one special character.")

        # Check if the new password matches the confirmation password
        if request.new_password != request.confirm_password:
            raise HTTPException(
                status_code=400, detail="New password and confirmation password do not match")

        # Check if the provided reset token is valid and not expired
        existing_otp = db.query(OTP).filter(OTP.email == email).first()
        if not existing_otp:
            raise HTTPException(status_code=404, detail='Link Expired ')

         # Check if the reset token is expired
        current_time = datetime.utcnow()
        if current_time > existing_otp.expiration_timestamp:
            raise HTTPException(
                status_code=400, detail='Reset token has expired')

        # Check if the provided reset token matches the one stored in the database
        if request.reset_token != existing_otp.reset_token:
            raise HTTPException(status_code=400, detail='Invalid reset token')

        # Hash the new password
        hashed_password = bcrypt.hash(request.new_password)

        # Update the password in the database
        user.password = hashed_password
        db.commit()

        # Remove the OTP record as the token is used
        delete_reset_token_from_database(db, email)

        return {'message': 'Password changed successfully'}

    except HTTPException as e:
        return {'error': e.detail}


def generate_alphanumeric_token(length=12):
    # Define the character set for alphanumeric tokens
    characters = string.ascii_letters + string.digits
    
    # Generate a random token of the specified length
    token = ''.join(secrets.choice(characters) for _ in range(length))
    
    return token
######################################

async def Create_team(teamcreate: TeamCreate,
                      current_user: UserInDB = Depends(get_current_active_user),
                      db:Session = Depends(get_db)):  
    
    try: 
        db = SessionLocal()  
        
       
        exist_team=  db.query(TeamCreateBase).filter(TeamCreateBase.teamname == teamcreate.teamname).first()
        

        get_user=  db.query(UserDB).filter(UserDB.email == current_user.email).first()
        
       
        

        if exist_team is not None:
            raise HTTPException(status_code=404, detail="Team is already exists")
        
        else:
            db_team=TeamCreateBase(
                                   
                                    teamname=teamcreate.teamname,
                                    description=teamcreate.description,
                                    team_link='',
                                    created_at=datetime.utcnow(),
                                    updated_at=datetime.utcnow(),
                                    deleted_status=teamcreate.deleted_status
                                    )
            
            db.add(db_team)  
            db.commit()    

            team_link=str(db_team.id)
            team_url=f"http://127.0.0.1:8000/join_grp/?token={team_link}"
    
            db_team.team_link=team_url
            db.commit()

            
            if get_user:
                   
                    admin=AddMemberBase(team_id=db_team.id,member=get_user.name,joined=True,role="super admin")
                    db.add(admin)
                    db.commit()

            return {'message':'team has been created successfully','team id':db_team.id}
 
    except Exception as e:
    # Handle database or other exceptions appropriately
        return {"error": str(e)}
    
Base.metadata.create_all(bind=engine)



async def Send_Team_Link(member:TeamMember,
                          current_user: UserInDB = Depends(get_current_active_user),
                          db:Session = Depends(get_db)):
    
    db=SessionLocal()

    team_id=member.team_id
    member_list=member.members
   
    team = db.query(TeamCreateBase).filter(TeamCreateBase.id == team_id).first()

   
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    
    else:

        for user in member_list:
            token = generate_alphanumeric_token()
            
            verify_user=db.query(UserDB).filter(UserDB.name == user).first()
          
            if not verify_user:
                return {'error': 'user not found'}
            else:
                mail = MessageSchema(
                    subject="Group Invite Link",
                    recipients=[verify_user.email],
                    body=f"Please click on the link below to join {team.teamname} group:\n\n{team.team_link + f'_{token}'}",
                    subtype=MessageType.html
                )
                await fast_mail.send_message(mail)
             
            add_member_db= AddMemberBase(team_id=team.id,member=user,token=token)
            db.add(add_member_db)
            db.commit()

    
        return{'detail':'send mail successfully'}



async def Join_Team(token: str,db:Session = Depends(get_db)):
    team_id = token.split("_")[0]
    
    team_token = token.split("_")[1]
    
    results = db.query(AddMemberBase).filter(AddMemberBase.team_id == team_id, AddMemberBase.token == team_token).first()
  
    if results is None:
            raise HTTPException(status_code=404, detail="User not found")
    if results.member==results.member:
        results.joined = True
        db.commit()
    return {"team_id": team_id,"token":results.member}



async def Assign_Role(member:str,role:str=None,
                      current_user: UserInDB = Depends(get_current_active_user),
                      db:Session = Depends(get_db)):

    get_member = db.query(AddMemberBase).filter(AddMemberBase.member == member, AddMemberBase.joined == True).first()
    print(get_member.member)

    super_admin = db.query(AddMemberBase).filter(AddMemberBase.role == "super admin").first()
    print('super_admin',super_admin)

    # if get_member.role == "super admin":
    if super_admin:
        if get_member.role is None:
            if role == "admin" or role == "drug assistant":
                get_member.role = role
                db.commit()
                return{'message':f"{get_member.member} is now {role}"}
            else:
        
                return {'error':"Only assign admin or drug assitant role  "}

       
        if role == None:
            get_member.role=None
            db.commit()
            return {'message':"Remove role"}
    else:
         return {'error':"Only super admin can assign role"}

        

async def Get_Team_Members(teamid:int,
                        #    current_user: UserInDB = Depends(get_current_active_user),
                           db:Session = Depends(get_db)):
    # db=SessionLocal()
    results = db.query(AddMemberBase).filter(AddMemberBase.team_id == teamid, AddMemberBase.joined == True).all()
    print('results',results)
    member = []
    for i in results:
        member.append(i.__dict__['member'])
    return {"members" :  member}

            
async def Remove_Member(teamid:int,
                        member:str,
                        current_user: UserInDB = Depends(get_current_active_user),
                        db:Session = Depends(get_db)):
    get_member = db.query(AddMemberBase).filter(AddMemberBase.member == member,AddMemberBase.team_id==teamid, AddMemberBase.joined == True).first()

    super_admin = db.query(AddMemberBase).filter(AddMemberBase.role == "super admin").first()
    if super_admin:
        db.delete(get_member)
        db.commit()
        return {"message": f"Removed {get_member.member} from team {get_member.team_id}"}
    
    else:
         return {'error':"Only super admin can delete member"}


async def Delete_Team(team_id, 
                      current_user: UserInDB = Depends(get_current_active_user),
                      db:Session = Depends(get_db)):
    
    team = db.query(TeamCreateBase).filter(TeamCreateBase.id == team_id).first()
   

    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    
    # Soft delete by updating the 'deleted_status' field
    # team.deleted_status = True
    db.delete(team)
    db.commit()
    
    return {"message": "Team deleted successfully"}



async def Get_Team(db:Session = Depends(get_db),
                   current_user: UserInDB = Depends(get_current_active_user)):

    getteam=db.query(TeamCreateBase).all()
    teams=[]

    for team in getteam:
        if team.deleted_status == False:
            teams.append(team.teamname)
          
   
    return {"message": "Get all teams",'Team':teams}



async def Get_Team_ById(team_name,
                        current_user: UserInDB = Depends(get_current_active_user),
                        db:Session = Depends(get_db)):

    
    getteam = db.query(TeamCreateBase).filter(TeamCreateBase.teamname == team_name).first()

    if getteam.deleted_status == True:

            
        return {'Team':getteam}
    
    elif getteam.deleted_status == False:
        raise HTTPException(status_code=404, detail='Team not found')
    


async def Update_Team(team_id, teamcreate:TeamCreate ,
                      current_user: UserInDB = Depends(get_current_active_user),
                      db:Session = Depends(get_db)):

    exist_team=  db.query(TeamCreateBase).filter(TeamCreateBase.id == team_id).first()
  

    team_link= str(exist_team.id)
    team_url=f"http://127.0.0.1:8000/join_grp/?token={team_link}"
    


    if exist_team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    
    else:

        for field, value in teamcreate.dict().items():
         
            if value is not None:
                 
                setattr(exist_team, field, value)

                if field == "team_link":
                    exist_team.team_link =  team_url
                    print('exist_team.team_link',exist_team.team_link)
            
        db.commit()
        db.refresh(exist_team)
      
        return {"message": "Team details updated", "updated_team": exist_team}

    




########################################## edit profile

async def edit_profile(
    name: str = None,
    email: str = None,
    contactno: str = None,
    file: UploadFile = None,
    db: Session = Depends(get_db)
):
    try:
        # Check if the user exists in the database
        user = db.query(UserDB).filter(UserDB.name == name).first()
       
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Initialize a flag to track whether data should be saved
        save_data = False

        # Check if either the file or name is provided
        if file is not None or name:
            # If the file is provided, process it
            if file is not None:
                file_content = await file.read()
                user.profile_picture_filename = file.filename
                user.profile_picture_data = file_content
                save_data = True

            # Update the fields in the user's profile if provided
            if name is not None:
                user.name = name
                save_data = True
            if email is not None:
                user.email = email
                save_data = True
            if contactno is not None:
                contactno_str = str(contactno)
                if len(contactno_str) == 10:
                    user.contactno = contactno_str
                    save_data = True
                else:
                    raise HTTPException(status_code=400, detail="Invalid contact number length")

        # Check if any data was saved, and return a response accordingly
        if save_data:
            # Commit the changes to the database
            db.commit()
            return {"message": "Data has been updated successfully"}
        else:
            # Return a message if neither the file nor name is provided
            return {"message": "No data provided, nothing saved in the database"}

    except Exception as e:
        # Handle database or other exceptions appropriately
        return {"error": str(e)}
    

async def Delete_Profile_Photo(name=str,
                               db: Session = Depends(get_db)):
    
    get_user=db.query(UserDB).filter(UserDB.name == name).first()

    if not get_user:
            raise HTTPException(status_code=404, detail="User not found")
    

    if get_user.profile_picture_filename:
        get_user.profile_picture_filename = None
        db.commit()
        return{'message':'delete profile photo successfully'}
    else:
        return{'error':'profile photo is none'}
    





####################################################

# async def Create_Demo(demo:Demo,db:Session = Depends(get_db)):

#     db=SessionLocal()

#     db_demo=DemoBase(

#             name=demo.name,
#             city=demo.city
#                     )
    

#     db.add(db_demo)
#     db.commit()
#     return {"message":"save data into demo table"}

# import csv

# async def export_demo_data(id:int,db:Session = Depends(get_db)):


#     get_demo_data=db.query(DemoBase).filter(DemoBase.id == id).first()
  

#     if not get_demo_data:
#         raise HTTPException(status_code=404, detail="Demo data not found")
    

#     list1=[]
#     for i in DemoBase.__table__.columns:
#         list1.append(i.name)

#     csv_filename=f"export_data_{get_demo_data.name}.csv"

#     with open(csv_filename, "w", newline="") as csvfile:
#             write = csv.writer(csvfile)
#             write.writerow(list1)
#             write.writerow([get_demo_data.id,get_demo_data.name,get_demo_data.city])

#     return {"message": "Data stored in CSV file"}




from typing import List
import csv


async def export_demo_data(ids:List[int],db:Session = Depends(get_db)):

    print('ids',ids)
    for id in ids:
        print('id',id)
        get_demo_data=db.query(DemoBase).filter(DemoBase.id == id).first()
        print('get_demo_data.name',get_demo_data.name)
  

        if not get_demo_data:
            raise HTTPException(status_code=404, detail=f"Demo data not found for Id{id}")
        

        list1=[]
        for i in DemoBase.__table__.columns:
            list1.append(i.name)

        csv_filename=f"export_data_{get_demo_data.name}_{id}.csv"

        with open(csv_filename, "w", newline="") as csvfile:
                write = csv.writer(csvfile)
                write.writerow(list1)
                write.writerow([get_demo_data.id,get_demo_data.name,get_demo_data.city])

    return {"message": "Data stored in CSV file"}


    









