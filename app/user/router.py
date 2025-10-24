from fastapi import APIRouter, Depends, HTTPException, status,Security
from app.model import Admin,Employee,LoginDetails
from app.database import get_session
from sqlmodel import Session, select
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt,JWTError
from typing import Optional,Type, List
from fastapi.security import OAuth2PasswordBearer
from app.user.schemas import adminDetail,tokenResponse,loginDetail,userUpdate,employeeDetail,adminUpdate

SECRET_KEY = "12354477463543"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
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
    now = datetime.now()
    login_entry = LoginDetails(
        userEmail=user.email,
        logInTime=now.time(),
        dateOfLoginLogOut=now.date(),
        token=accessToken
    )

    session.add(login_entry)
    session.commit()
    session.refresh(login_entry)
    return {"accessToken": accessToken, "tokenType": "bearer"}

@user_app.post("/admin/logout")
def logout(current_user: Admin = Depends(get_current_user), session: Session = Depends(get_session)):
    now = datetime.now()
    login_entry = session.exec(select(LoginDetails).where(LoginDetails.userEmail == current_user.email).order_by(LoginDetails.id.desc())).first()
    if login_entry and not login_entry.logOutTime:
        login_entry.logOutTime = now.time()
        session.add(login_entry)
        session.commit()
        session.refresh(login_entry)

    return {"message": f"{login_entry.userEmail} Logged out successfully"}

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
    
@user_app.get("/employee/details")
def view_employee_details(employeeEmail: str, session: Session = Depends(get_session)):
    # Find employee by email
    employee = session.exec(
        select(Employee).where(Employee.email == employeeEmail)
    ).first()

    # If not found → 404
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    # If inactive → deny access
    if not employee.isActive:
        raise HTTPException(status_code=403, detail="Access denied. Employee account is not active.")

    # If active → show details
    return {
        "Role": "Employee",
        "Details": {
            "email": employee.email,
            "first_name": employee.userFirstName,
            "last_name": employee.userLastName,
            "phone_number": employee.phoneNumber,
            "address": employee.address,
            "isActive": employee.isActive
        }
    }

def fetch_users(model: Type, session: Session, email: Optional[str] = None, isActive: Optional[bool] = None) -> List:
    query = select(model)
    if email:
        query = query.filter(model.email == email)
    if isActive is not None:
        query = query.filter(model.isActive == isActive)
    return session.exec(query).all()


@user_app.get("/admin/employee/details")
def admin_view_user_details(
    userEmail: Optional[str] = None,
    allAdmin: Optional[bool] = None,
    allEmployee: Optional[bool] = None,
    all: Optional[bool] = None,
    isActive: Optional[bool] = None,
    current_user = Security(get_current_user),
    session: Session = Depends(get_session)
):
    
    current_admin = fetch_users(Admin, session, email=current_user.email)
    if not current_admin:
        raise HTTPException(status_code=403, detail="Only admin can access this endpoint")
    if not current_admin[0].isActive:
        raise HTTPException(status_code=403, detail="Access denied. Admin account is not active.")

    if userEmail:
        admins = fetch_users(Admin, session, email=userEmail)
        if admins:
            admin_data = admins[0]
            return {
                "Role": "Admin",
                "Details": {
                    "email": admin_data.email,
                    "first_name": admin_data.userFirstName,
                    "last_name": admin_data.userLastName,
                    "phone_number": admin_data.phoneNumber,
                    "isActive": admin_data.isActive
                }
            }

        employees = fetch_users(Employee, session, email=userEmail, isActive=isActive)
        if employees:
            emp_data = employees[0]
            return {
                "Role": "Employee",
                "Details": {
                    "email": emp_data.email,
                    "first_name": emp_data.userFirstName,
                    "last_name": emp_data.userLastName,
                    "phone_number": emp_data.phoneNumber,
                    "isActive": emp_data.isActive
                }
            }

        raise HTTPException(status_code=404, detail="No admin or employee found with the given email")

    if allAdmin:
        admins = fetch_users(Admin, session, isActive=isActive)
        return {
            "Role": "Admin",
            "Count": len(admins),
            "Details": [
                {
                    "email": a.email,
                    "first_name": a.userFirstName,
                    "last_name": a.userLastName,
                    "phone_number": a.phoneNumber,
                    "isActive": a.isActive
                } for a in admins
            ]
        }
    
    if allEmployee:
        employees = fetch_users(Employee, session, isActive=isActive)
        return {
            "Role": "Employee",
            "Count": len(employees),
            "Details": [
                {
                    "email": e.email,
                    "first_name": e.userFirstName,
                    "last_name": e.userLastName,
                    "phone_number": e.phoneNumber,
                    "isActive": e.isActive
                } for e in employees
            ]
        }
    
    if all:
        admins = fetch_users(Admin, session, isActive=isActive)
        employees = fetch_users(Employee, session, isActive=isActive)
        return {
            "Admins_Count": len(admins),
            "Employees_Count": len(employees),
            "Admins": [
                {
                    "email": a.email,
                    "first_name": a.userFirstName,
                    "last_name": a.userLastName,
                    "phone_number": a.phoneNumber,
                    "isActive": a.isActive
                } for a in admins
            ],
            "Employees": [
                {
                    "email": e.email,
                    "first_name": e.userFirstName,
                    "last_name": e.userLastName,
                    "phone_number": e.phoneNumber,
                    "isActive": e.isActive
                } for e in employees
            ]
        }
    raise HTTPException(status_code=400, detail="Please provide valid parameters (userEmail, allAdmin, allEmployee, or all)")

    
# @user_app.get("/admin/employee/details")
# def admin_view_user_details(
#     userEmail: str,  
#     isActive: Optional[bool] = None,
#     current_user = Security(get_current_user),
#     session: Session = Depends(get_session)
# ):
#     admin = session.exec(select(Admin).where(Admin.email == current_user.email)).first()

#     if not admin:
#         raise HTTPException(status_code=403, detail="Only admin can access this endpoint")

#     if not admin.isActive:
#         raise HTTPException(status_code=403, detail="Access denied. Admin account is not active.")

#     if userEmail is not None:
#         target_admin = session.exec(select(Admin).where(Admin.email == userEmail)).first()
#         if target_admin:

#             if isActive is not None and target_admin.isActive != isActive:
#                 raise HTTPException(status_code=404, detail="Admin not found with requested active status")

#             return {
#                 "Role": "Admin",
#                 "Details": {
#                     "email": target_admin.email,
#                     "first_name": target_admin.userFirstName,
#                     "last_name": target_admin.userLastName,
#                     "phone_number": target_admin.phoneNumber,
#                     "isActive": target_admin.isActive
#                 }
#             }
    
#         query = select(Employee).where(Employee.email == userEmail)
#         if isActive is not None:
#             query = query.where(Employee.isActive == isActive)

#         employee = session.exec(query).first()
#         if employee:
#             return {
#                 "Role": "Employee",
#                 "Details": {
#                     "email": employee.email,
#                     "first_name": employee.userFirstName,
#                     "last_name": employee.userLastName,
#                     "phone_number": employee.phoneNumber,
#                     "isActive": employee.isActive
#                 }
#             }
#         raise HTTPException(status_code=404, detail="No admin or employee found with the given email")

# @user_app.get("/admin/employee/list/isNotActive")
# def employee_lis(adminOrEmployeeEmail:str,session:Session=Depends(get_session)):
#     employee_or_admin = session.exec(select(Admin).where(Admin.email == adminOrEmployeeEmail,Admin.isActive==False)).first()
#     if employee_or_admin and Security(get_current_user) :
#         return{"Role": "Admin",
#             "Details": {
#                 "email": employee_or_admin.email,
#                 "first_name": employee_or_admin.userFirstName,
#                 "last_name": employee_or_admin.userLastName,
#                 "phone_number": employee_or_admin.phoneNumber
#             }}
#     else:
#         employee_or_admin = session.exec(select(Employee).where(Employee.email == adminOrEmployeeEmail,Employee.isActive==False)).first()
#         return{"Details":employee_or_admin}

# @user_app.get("/admin/employee/list/isActive")
# def employee_lis(adminOrEmployeeEmail:str,session:Session=Depends(get_session)):
#     employee_or_admin = session.exec(select(Admin).where(Admin.email == adminOrEmployeeEmail,Admin.isActive==True)).first()
#     if employee_or_admin and Security(get_current_user):
#         return{"Role": "Admin",
#             "Details": {
#                 "email": employee_or_admin.email,
#                 "first_name": employee_or_admin.userFirstName,
#                 "last_name": employee_or_admin.userLastName,
#                 "phone_number": employee_or_admin.phoneNumber
#             }}
#     else:
#         employee_or_admin = session.exec(select(Employee).where(Employee.email == adminOrEmployeeEmail,Employee.isActive==True)).first()
#         return{"Details":employee_or_admin}


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
    record.scheduledDeletion = datetime.now() + timedelta(hours=3)
    session.add(record)
    session.commit()

    return {"message": f"User with email '{adminOrEmployeeEmail}' marked inactive. Will be deleted after 3 hours."}

