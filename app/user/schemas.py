from pydantic import BaseModel
from typing import Optional

class tokenResponse(BaseModel):
    accessToken: str
    tokenType: str = "bearer"

class loginDetail(BaseModel):
    email:str
    password:str

class adminDetail(BaseModel):
    userFirstName: str
    userLastName : str
    designation: str
    password: str
    email:str
    address: Optional[str]=None
    phoneNumber: str
    isSuperUser: bool 

class employeeDetail(BaseModel):
    userFirstName: str
    userLastName : str
    designation: str
    email: str
    address: Optional[str]=None
    phoneNumber: str

class userUpdate(BaseModel):
    email:Optional[str] = None
    userFirstName: Optional[str] = None
    userLastName : Optional[str] = None
    address: Optional[str] = None
    phoneNumber: Optional[str] = None
    designation: Optional[str] = None

class adminUpdate(BaseModel):
    email: Optional[str] = None
    userFirstName: Optional[str] = None
    userLastName : Optional[str] = None
    address: Optional[str] = None
    phoneNumber: Optional[str] = None
    designation: Optional[str] = None
    password:Optional[str]=None