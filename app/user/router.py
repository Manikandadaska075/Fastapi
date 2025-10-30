from fastapi import APIRouter, Depends, HTTPException, status, Security
from app.model import User, LoginDetails
from app.database import get_session
from sqlmodel import Session, select, and_
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError, ExpiredSignatureError
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from app.user.schemas import tokenResponse, loginDetail, userUpdate, userDetail

SECRET_KEY = "12354477463543"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire}) 
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    not_logged_in = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User is not logged in or token is invalid",
                                  headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise not_logged_in
        
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Token has expired. Please log in again.",
                            headers={"WWW-Authenticate": "Bearer"})
    except JWTError:
        raise not_logged_in
    
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User not found. Please log in again.")
    if not user.isActive:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="User account is inactive. Contact admin.")
    return user

user_app = APIRouter()

@user_app.post("/admin/registration")
def get_admin_dashboard(user: userDetail, session: Session = Depends(get_session)):
    if user.designation.lower() != "hr":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only HR designation is allowed to register as admin")
    existing_user = session.exec(select(User).where(User.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already taken")
    db = User(email=user.email,userFirstName=user.userFirstName,userLastName=user.userLastName,password=hash_password(user.password),
               designation=user.designation,phoneNumber=user.phoneNumber,isSuperUser=user.isSuperUser,address=user.address)
    session.add(db)
    session.commit()
    session.refresh(db)
    return db

@user_app.post("/login", response_model=tokenResponse)
def login(form_data: loginDetail, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form_data.email)).first()
    if not user.isActive:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User is not active")
    if not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user.email})
    now = datetime.now()
    login_entry = LoginDetails(userEmail=user.email,logInTime=now.time(),dateOfLoginLogOut=now.date(),token=access_token)
    session.add(login_entry)
    session.commit()
    session.refresh(login_entry)
    return {
        "accessToken": access_token,
        "tokenType": "bearer"
    }

@user_app.post("/logout")
def logout(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    now = datetime.now()
    login_entry = session.exec(select(LoginDetails).where(LoginDetails.userEmail == current_user.email).order_by(LoginDetails.id.desc())).first()
    if login_entry and not login_entry.logOutTime:
        login_entry.logOutTime = now.time()
        session.add(login_entry)
        session.commit()
        session.refresh(login_entry)
    return {"message": f"{login_entry.userEmail} Logged out successfully"}

@user_app.post("/employee/creation")
def employee_creation(creation: userDetail,current_user: User = Security(get_current_user),session: Session = Depends(get_session)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not current_user.isSuperUser:
        raise HTTPException(status_code=403, detail="Only admins can create employees")
    existing_user = session.exec(select(User).where(User.email == creation.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = hash_password(creation.password)
    employee = User(email=creation.email,password=hashed_password,userFirstName=creation.userFirstName,userLastName=creation.userLastName,
                    designation=creation.designation, phoneNumber=creation.phoneNumber,address=creation.address,isActive=True,
                    isSuperUser=False)
    session.add(employee)
    session.commit()
    session.refresh(employee)
    return {"message": "Employee created successfully", "employee": 
            {
                "email": employee.email,
                "first_name": employee.userFirstName,
                "last_name": employee.userLastName,
                "phone_number": employee.phoneNumber,
                "address": employee.address,
                "isActive": employee.isActive,
                "isSuperUser": employee.isSuperUser,
            }
        }

@user_app.get("/employee/details")
def view_employee_details(current_user: User = Security(get_current_user), session: Session = Depends(get_session)):
    employee = session.exec(select(User).where(User.email == current_user.email)).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    if not employee.isActive:
        raise HTTPException(status_code=403, detail="Access denied. Employee account is not active.")
    return {
        "Role": "Employee",
        "Details": {
            "email": employee.email,
            "first_name": employee.userFirstName,
            "last_name": employee.userLastName,
            "phone_number": employee.phoneNumber,
            "address": employee.address,
            "isActive": employee.isActive,
            "designation":employee.designation
        }
    }

@user_app.get("/admin/details")
def view_admin_details(current_user: User = Security(get_current_user), session: Session = Depends(get_session)):
    admin = session.exec(select(User).where(User.email == current_user.email)).first()
    if not current_user.isSuperUser:
        raise HTTPException(status_code=403, detail="Only admins can view there details")
    if not current_user.isActive:
        raise HTTPException(status_code=403, detail="Access denied. Account is not active.")
    if not admin:
        raise HTTPException(status_code=404, detail="Admin is not found")
    return {
        "Role": "Admin",
        "Details": {
            "email": admin.email,
            "first_name": admin.userFirstName,
            "last_name": admin.userLastName,
            "phone_number": admin.phoneNumber,
            "address": admin.address,
            "isActive": admin.isActive
        }
    }

@user_app.get("/all/admin/details/views")
def all_admin_details_views(current_user: User = Security(get_current_user), session: Session = Depends(get_session)):
    admin = session.exec(select(User).where(User.isSuperUser == True)).all()
    if not current_user.isSuperUser:
        raise HTTPException(status_code=403, detail="Only admins can view there details")
    if not current_user.isActive:
        raise HTTPException(status_code=403, detail="Access denied. Account is not active.")
    if not admin:
        raise HTTPException(status_code=404, detail="Admin is not found")
    return {
        "Role": "Admin",
        "Count": len(admin),
        "Details":[ {
                "email": ad.email,
                "first_name": ad.userFirstName,
                "last_name": ad.userLastName,
                "phone_number": ad.phoneNumber,
                "address": ad.address,
                "isActive": ad.isActive,
                "isSuperUser": ad.isSuperUser
            }
            for ad in admin
        ],
        }

@user_app.get("/admin/views/employee/details")
def admin_view_employee_details(employeeEmail: Optional[str] = None,current_user: User = Security(get_current_user),
                          session: Session = Depends(get_session)):
    
    if not current_user.isActive:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Account is not active.")
    
    if not current_user.isSuperUser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can view employee details.")

    if employeeEmail:
        employee = session.exec(
            select(User).where(and_(User.email == employeeEmail, User.isActive == True, User.isSuperUser == False))).first()
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")
        
        return {
            "Role": "Employee",
            "Details": {
                "email": employee.email,
                "first_name": employee.userFirstName,
                "last_name": employee.userLastName,
                "phone_number": employee.phoneNumber,
                "address": employee.address,
                "isActive": employee.isActive,
                "isSuperUser": employee.isSuperUser,
            }
        }

    employees = session.exec(select(User).where(and_(User.isSuperUser == False, User.isActive == True))).all()

    if not employees:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active employees found")

    return {
        "Role": "All Employee Details",
        "Count": len(employees),
        "Details": [
            {
                "email": emp.email,
                "first_name": emp.userFirstName,
                "last_name": emp.userLastName,
                "phone_number": emp.phoneNumber,
                "address": emp.address,
                "isActive": emp.isActive,
                "isSuperUser": emp.isSuperUser,
            }
            for emp in employees
        ],
    }

@user_app.get("/admin/views/all/not/active/employee/details")
def admin_view_not_active_employee_details(current_user: User = Security(get_current_user),
                          session: Session = Depends(get_session)):
    employee = session.exec(select(User).where(User.isActive == False, User.isSuperUser == False)).all()
    if not current_user.isSuperUser:
        raise HTTPException(status_code=403, detail="Only admins can view details")
    if not current_user.isActive:
        raise HTTPException(status_code=403, detail="Access denied. Account is not active.")
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    return {
        "Role": "Employee",
        "Count": len(employee),
        "Details": [
            {
                "email": emp.email,
                "first_name": emp.userFirstName,
                "last_name": emp.userLastName,
                "phone_number": emp.phoneNumber,
                "address": emp.address,
                "isActive": emp.isActive,
                "isSuperUser": emp.isSuperUser,
            }
            for emp in employee
        ],
    }

@user_app.patch("/admin/profile/update")
def admin_profile_update(data: userUpdate, current_user: User = Security(get_current_user),session: Session = Depends(get_session)):
    
    admin = session.exec(select(User).where(User.email == current_user.email)).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin is not logged in")
    
    if not current_user.isSuperUser:
        raise HTTPException(status_code=403, detail="Only admins can view details")
    
    if not current_user.isActive:
        raise HTTPException(status_code=403, detail="Access denied. Account is not active.")
    
    if data.password:
        data.password = hash_password(data.password)

    update_data = data.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(admin, key, value)
    session.add(admin)
    session.commit()
    session.refresh(admin)

    return {"message": "Admin profile updated successfully", "admin": 
            {
                "email": admin.email,
                "first_name": admin.userFirstName,
                "last_name": admin.userLastName,
                "phone_number": admin.phoneNumber,
                "address": admin.address,
                "isActive": admin.isActive,
                "isSuperUser": admin.isSuperUser
            }
        }

@user_app.patch("/employee/profile/update")
def employee_profile_update( data: userUpdate, employeeEmail: Optional[str] =None, current_user: userDetail = Security(get_current_user),
                   session: Session = Depends(get_session)):

    user = session.exec(select(User).where(User.email == current_user.email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not logged in")
    
    if user.isSuperUser:
        if not employeeEmail:
            raise HTTPException(status_code=400, detail="Employee email is required for admin updates")
        employee = session.exec(select(User).where(User.email == employeeEmail)).first()
        if not employee:
            raise HTTPException(status_code=404, detail="Employee not found")
    else:
        employee = user

    if data.password:
        data.password = hash_password(data.password)

    update_data = data.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(employee, key, value)

    session.add(employee)
    session.commit()
    session.refresh(employee)
    return {"message": "Profile updated successfully", "employee": 
            {
                "email": employee.email,
                "first_name": employee.userFirstName,
                "last_name": employee.userLastName,
                "phone_number": employee.phoneNumber,
                "address": employee.address,
                "isActive": employee.isActive,
                "isSuperUser": employee.isSuperUser
            }
        }

@user_app.delete("/admin/employee/deletion")
def admin_or_employee_delete(adminOrEmployeeEmail: str,current_user: userDetail = Security(get_current_user),
                             session: Session = Depends(get_session)):
    
    admin = session.exec(select(User).where(User.email == current_user.email)).first()
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin is not logged in")
    if not admin.isSuperUser:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin can only delete the user")
    record = session.exec(select(User).where(User.email == adminOrEmployeeEmail)).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No admin or employee found with email: {adminOrEmployeeEmail}")
    if not record.isActive:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"admin or employee is not active : {adminOrEmployeeEmail}")
    record.isActive = False
    record.scheduledDeletion = datetime.now() + timedelta(hours=3)
    session.add(record)
    session.commit()
    return {"message": f"User with email '{adminOrEmployeeEmail}' marked inactive. Will be deleted after 3 hours."}