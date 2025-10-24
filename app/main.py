from fastapi import FastAPI
from apscheduler.schedulers.background import BackgroundScheduler
from app.database import init_db
from app.user.router import user_app
from app.cleanup import cleanup_inactive_users,update_logout_time

app = FastAPI(title="E-Commerce")
scheduler = BackgroundScheduler()

@app.on_event("startup")
def on_startup():
    init_db()
    cleanup_inactive_users()
    update_logout_time()
    scheduler.add_job(update_logout_time, "interval", minutes=2)
    scheduler.add_job(cleanup_inactive_users, "interval", hours=1)
    scheduler.start()

@app.on_event("shutdown")
def on_shutdown():
    scheduler.shutdown()

app.include_router(user_app, prefix="/fastapi/app/user")