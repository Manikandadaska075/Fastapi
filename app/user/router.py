from fastapi import APIRouter, Depends, HTTPException, status,Security
from app.model import Admin,Employee
from app.database import get_session
from sqlmodel import Session, select
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt,JWTError
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from app.user.schemas import admin_detail,TokenResponse,login_detail,Userupdate,employee_detail,Adminupdate

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

@user_app.post("/admin_registration")
def get_admin_dashboard(user: admin_detail, session: Session = Depends(get_session)):
    if user.designation.lower() != "hr":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR designation is allowed to register as admin"
        )
    existing_user = session.exec(select(Admin).where(Admin.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already taken")
    db = Admin(email=user.email,password=hash_password(user.password),designation= user.designation,is_superuser=user.is_superuser)
    session.add(db)
    session.commit()
    session.refresh(db)
    return db

@user_app.post("/login", response_model=TokenResponse)
def login(form_data: login_detail, session: Session = Depends(get_session)):
    user = session.exec(select(Admin).where(Admin.email == form_data.email)).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@user_app.post("/employee_creation")
def employee_creation(creation: employee_detail,current_user: admin_detail = Security(get_current_user),session:Session=Depends(get_session)):
    admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()
    if admin:
        employee = session.exec(select(Employee).where(Employee.email == creation.email)).first()
        if employee:
            raise HTTPException(status_code=400, detail="User already taken")
        db = Employee(email=creation.email,user_first_name=creation.user_first_name,user_last_name=creation.user_last_name,designation= creation.designation,phone_number=creation.phone_number,address=creation.address)
        session.add(db)
        session.commit()
        session.refresh(db)
        return db
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Admin is not logged in")
    
@user_app.put("/admin_profile_update")
def admin_profile_update(data: Adminupdate, current_user: admin_detail = Security(get_current_user), session: Session = Depends(get_session)):
    admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Admin is not logged in")
    if data.email is not None:
        admin.email = data.email
    if data.user_first_name is not None:
        admin.user_first_name = data.user_first_name
    if data.user_last_name is not None:
        admin.user_last_name = data.user_last_name
    if data.designation is not None:
        admin.designation = data.designation
    if data.phone_number is not None:
        admin.phone_number = data.phone_number
    if data.address is not None:
        admin.address = data.address

    session.add(admin)
    session.commit()
    session.refresh(admin)

    return admin

@user_app.put("/profile_update")
def update_profile(yourcurrentemail:str, data: Userupdate, current_user: admin_detail = Security(get_current_user), session: Session = Depends(get_session)):
    admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Admin is not logged in")

    employee = session.exec(select(Employee).where(Employee.email == yourcurrentemail)).first()
    if not employee:
        raise HTTPException(status_code=404, detail="User not found")
    
    if data.email is not None:
        employee.email = data.email
    if data.user_first_name is not None:
        employee.user_first_name = data.user_first_name
    if data.user_last_name is not None:
        employee.user_last_name = data.user_last_name
    if data.designation is not None:
        employee.designation = data.designation
    if data.phone_number is not None:
        employee.phone_number = data.phone_number
    if data.address is not None:
        employee.address = data.address

    session.add(employee)
    session.commit()
    session.refresh(employee)

    return employee
#add current user
# create separate table for admin(hr) and employees
#add api end point to create new employee by admin