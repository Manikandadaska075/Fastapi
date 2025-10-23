from fastapi import APIRouter, Depends, HTTPException, status,Security
from app.model import Admin,Employee
from app.database import get_session
from sqlmodel import Session, select
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt,JWTError
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from app.user.schemas import adminDetail,tokenResponse,loginDetail,userUpdate,employeeDetail,adminUpdate

SECRET_KEY = "12354477463543"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_current_user(token: str = Depends(oauth2_scheme),session: Session = Depends(get_session)):

    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},)
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    admin = session.exec(select(Admin).where(Admin.email == email)).first()
    if admin is None:
        raise credentials_exception
    
    return admin

user_app = APIRouter()

@user_app.post("/admin/registration")
def get_admin_dashboard(user: adminDetail, session: Session = Depends(get_session)):
    if user.designation.lower() != "hr":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR designation is allowed to register as admin"
        )
    existing_user = session.exec(select(Admin).where(Admin.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already taken")
    db = Admin(email=user.email,userFirstName=user.userFirstName,userLastName=user.userLastName,password=hash_password(user.password),designation=user.designation,phoneNumber=user.phoneNumber,isSuperUser=user.isSuperUser,address=user.address)
    session.add(db)
    session.commit()
    session.refresh(db)
    return db

@user_app.post("/admin/login", response_model=tokenResponse)
def login(form_data: loginDetail, session: Session = Depends(get_session)):
    user = session.exec(select(Admin).where(Admin.email == form_data.email)).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    accessToken = create_access_token(data={"sub": user.email})
    return {"accessToken": accessToken, "tokenType": "bearer"}

@user_app.post("/employee/creation")
def employee_creation(creation: employeeDetail,current_user: adminDetail = Security(get_current_user),session:Session=Depends(get_session)):
    admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()
    if admin:
        employee = session.exec(select(Employee).where(Employee.email == creation.email)).first()
        if employee:
            raise HTTPException(status_code=400, detail="User already taken")
        db = Employee(email=creation.email,userFirstName=creation.userFirstName, userLastName=creation.userLastName,designation= creation.designation,phoneNumber=creation.phoneNumber,address=creation.address)
        session.add(db)
        session.commit()
        session.refresh(db)
        return db
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Admin is not logged in")
    
@user_app.get("/admin/employee/list")
def employee_lis(adminOrEmployeeEmail:str,session:Session=Depends(get_session)):
    employee_or_admin = session.exec(select(Admin).where(Admin.email == adminOrEmployeeEmail)).first()
    if employee_or_admin:
        return{"Role": "Admin",
            "Details": {
                "email": employee_or_admin.email,
                "first_name": employee_or_admin.userFirstName,
                "last_name": employee_or_admin.userLastName,
                "phone_number": employee_or_admin.phoneNumber
            }}
    else:
        employee_or_admin = session.exec(select(Employee).where(Employee.email == adminOrEmployeeEmail)).first()
        return{"Details":employee_or_admin}

@user_app.patch("/admin/profile/update")
def admin_profile_update(data: adminUpdate,current_user: adminDetail = Security(get_current_user),session: Session = Depends(get_session)):

    admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin is not logged in")

    update_data = data.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(admin, key, value)

    session.add(admin)
    session.commit()
    session.refresh(admin)

    return {"message": "Admin profile updated successfully", "admin": admin}

@user_app.patch("/employee/profile/update")
def update_profile(yourcurrentemail: str, data: userUpdate, current_user: adminDetail = Security(get_current_user),session: Session = Depends(get_session)):

    admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin is not logged in")

    employee = session.exec(select(Employee).where(Employee.email == yourcurrentemail)).first()
    if not employee:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(employee, key, value)

    session.add(employee)
    session.commit()
    session.refresh(employee)
    return {"message": "Profile updated successfully", "employee": employee}

@user_app.delete("/admin/employee/deletion")
def delete_employee_or_admin(
    adminOrEmployeeEmail: str,
    current_user: adminDetail = Security(get_current_user),
    session: Session = Depends(get_session)):
    
    admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin is not logged in")

    record = session.exec(select(Admin).where(Admin.email == adminOrEmployeeEmail)).first()
    if not record:
        record = session.exec(select(Employee).where(Employee.email == adminOrEmployeeEmail)).first()

    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No admin or employee found with email: {adminOrEmployeeEmail}")

    record.isActive = False
    record.scheduledDeletion = datetime.utcnow() + timedelta(hours=3)
    session.add(record)
    session.commit()

    return {"message": f"User with email '{adminOrEmployeeEmail}' marked inactive. Will be deleted after 3 hours."}

