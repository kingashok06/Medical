<<<<<<< HEAD
from fastapi import APIRouter,HTTPException
from models.user_model import User
# from schemas.user_schema import users_serializer
from bson import ObjectId
from config.db import collection
# from .custom_exceptions import UserAlreadyExists, EmailAlreadyExists
import bcrypt

user = APIRouter()
=======
from fastapi import APIRouter
from api.api import startup_event, shutdown_event, verify_otp_endpoint, register_user, login_for_access_token, change_password, forgot_password, reset_password,Create_team,Get_Team,Get_Team_ById,Update_Team,Delete_Team,Send_Team_Link, Join_Team,Get_Team_Members,Assign_Role,Remove_Member,edit_profile,Delete_Profile_Photo,export_demo_data   #,Create_Demo
from models.user_model import UserResponse,TeamCreate #,Demo
from models.auth import Token


routes = APIRouter()

routes.on_event("startup")(startup_event)
routes.on_event("shutdown")(shutdown_event)
routes.post("/verify-otp")(verify_otp_endpoint)
routes.post("/register/", response_model=UserResponse)(register_user)
routes.post("/token", response_model=Token)(login_for_access_token)
routes.put("/change_password/")(change_password)
routes.post('/forgot_password')(forgot_password)
routes.post('/reset_password')(reset_password)




####################
routes.post("/create_team/")(Create_team)
routes.post('/send_team_link')(Send_Team_Link)
routes.get("/join_team/{token}")(Join_Team)
routes.post('/assign_role')(Assign_Role)
routes.get("/get_team_members")(Get_Team_Members)
routes.delete('/remove_member/')(Remove_Member)
routes.get("/get_team")(Get_Team)
routes.get("/get_team/{team_name}")(Get_Team_ById)
routes.delete('/delete_team/{team_id}')(Delete_Team)
routes.put("/update_team/{team_id}")(Update_Team)



routes.put('/edit_profile/{name}')(edit_profile)
routes.delete('/delete_profile_photo/{name}')(Delete_Profile_Photo)


# routes.post("/create_demo")(Create_Demo)
routes.post("/export_demo_data/{id}")(export_demo_data)

>>>>>>> 732d2d0 (Team_APIs)




