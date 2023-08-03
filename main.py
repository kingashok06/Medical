from fastapi import FastAPI
from routes.user_routes import user
# from routes.user_routes import app
app = FastAPI()

@app.get("/")
async def home():
    return {"message": "Hello World"}


app.include_router(user)
# app.include_router(app)



