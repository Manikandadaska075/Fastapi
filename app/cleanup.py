from datetime import datetime,timedelta
from sqlmodel import Session, select
from app.database import get_engine, get_session
from app.model import User, LoginDetails

def cleanup_inactive_users():
    engine = get_engine()
    with Session(engine) as session:
        now = datetime.now()
        user_deletion = session.exec(
            select( User).where(User.isActive == False,User.scheduledDeletion != None,User.scheduledDeletion <= now)).all()
        for record in user_deletion:
            session.delete(record)
        session.commit()
        print(f"[CLEANUP JOB] Deleted {len(user_deletion)} inactive users at {now}.")

def update_logout_time():
    with next(get_session()) as session:
        now = datetime.now()
        expired_entries = session.exec(select(LoginDetails)).all()

        for entry in expired_entries:
            token_expiry_time = datetime.combine(entry.dateOfLoginLogOut, entry.logInTime) + timedelta(minutes=10)
            if token_expiry_time <= now and entry.logOutTime is None:
                entry.logOutTime = token_expiry_time.time()
                session.add(entry)
        
        session.commit()

