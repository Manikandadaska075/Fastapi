from fastapi import FastAPI
from app.database import init_db
from app.user.router import user_app

app = FastAPI(title="E-Commerce")

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(user_app)