from fastapi import FastAPI,HTTPException

from pydantic import BaseModel
from routes.login_routes import user


app=FastAPI()



# @app.get("/login")

# def login():
#     # return {"msg": "run first app using fastapi"}
#     return "hello"


from fastapi import FastAPI

# from routes.user_routes import app
app = FastAPI()

@app.get("/")
async def home():
    return {"message": "Hello World"}


app.include_router(user)


