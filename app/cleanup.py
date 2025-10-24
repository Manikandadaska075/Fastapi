from datetime import datetime,timedelta
from sqlmodel import Session, select
from app.database import get_engine, get_session
from app.model import Admin, Employee, LoginDetails

def cleanup_inactive_users():
    engine = get_engine()
    with Session(engine) as session:
        now = datetime.now()

        admins_to_delete = session.exec(
            select(Admin).where(
                Admin.isActive == False,
                Admin.scheduledDeletion != None,
                Admin.scheduledDeletion <= now
            )
        ).all()

        employees_to_delete = session.exec(
            select(Employee).where(
                Employee.isActive == False,
                Employee.scheduledDeletion != None,
                Employee.scheduledDeletion <= now
            )
        ).all()

        for record in admins_to_delete + employees_to_delete:
            session.delete(record)

        session.commit()
        print(f"[CLEANUP JOB] Deleted {len(admins_to_delete) + len(employees_to_delete)} inactive users at {now}.")

def update_logout_time():
    with next(get_session()) as session:
        now = datetime.now()
        expired_entries = session.exec(select(LoginDetails)).all()

        for entry in expired_entries:
            token_expiry_time = datetime.combine(entry.dateOfLoginLogOut, entry.logInTime) + timedelta(minutes=5)
            if token_expiry_time <= now and entry.logOutTime is None:
                entry.logOutTime = now.time()
                session.add(entry)
        
        session.commit()

