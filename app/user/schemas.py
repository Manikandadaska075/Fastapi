from pydantic import BaseModel
from typing import Optional

class admin_detail(BaseModel):
    email:str
    password: str
    designation: str
    is_superuser: bool 

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class login_detail(BaseModel):
    email:str
    password:str

class Userupdate(BaseModel):
    email:Optional[str] = None
    user_first_name: Optional[str] = None
    user_last_name : Optional[str] = None
    address: Optional[str] = None
    phone_number: Optional[str] = None
    designation: Optional[str] = None

class Adminupdate(BaseModel):
    email: Optional[str] = None
    user_first_name: Optional[str] = None
    user_last_name : Optional[str] = None
    address: Optional[str] = None
    phone_number: Optional[str] = None
    designation: Optional[str] = None
    password:Optional[str]=None

class employee_detail(BaseModel):
    email: str
    user_first_name: str
    user_last_name : str
    address: str
    phone_number: str
    designation: str