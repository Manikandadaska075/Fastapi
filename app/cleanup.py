from datetime import datetime, timedelta
from sqlmodel import Session, select
from app.database import get_engine, get_session
from app.model import User, LoginDetails

def cleanup_inactive_users():
    engine = get_engine()
    with Session(engine) as session:
        now = datetime.now()
        users_to_delete = session.exec(
            select(User).where(User.isActive == False,User.scheduledDeletion != None,User.scheduledDeletion <= now)).all()
        for user in users_to_delete:
            login_records = session.exec(select(LoginDetails).where(LoginDetails.userEmail == user.email)).all()
            for login in login_records:
                session.delete(login)
            session.delete(user)
        session.commit()
        print(f"[CLEANUP JOB] Deleted {len(users_to_delete)} inactive users at {now}.")

def update_logout_time():
    with next(get_session()) as session:
        now = datetime.now()
        expired_entries = session.exec(select(LoginDetails).where(LoginDetails.logOutTime.is_(None))).all()

        for entry in expired_entries:
            token_expiry_time = datetime.combine(entry.dateOfLoginLogOut, entry.logInTime) + timedelta(minutes=10)
            if token_expiry_time <= now and entry.logOutTime is None:
                entry.logOutTime = token_expiry_time.time()
                session.add(entry)
        
        session.commit()

