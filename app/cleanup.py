from datetime import datetime
from sqlmodel import Session, select
from app.database import get_engine
from app.model import Admin, Employee

def cleanup_inactive_users():
    engine = get_engine()
    with Session(engine) as session:
        now = datetime.utcnow()

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
