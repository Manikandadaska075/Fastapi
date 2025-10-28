from sqlmodel import SQLModel, Field
from typing import *
from datetime import time, date , datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    userFirstName: str
    userLastName : str 
    designation :str
    password: str
    email: str
    address: Optional[str] = None
    phoneNumber: str
    isActive: bool = True
    isSuperUser: bool = False 
    scheduledDeletion: Optional[datetime] = None

class LoginDetails(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    userEmail: str
    logInTime: time
    logOutTime: Optional[time] = None
    dateOfLoginLogOut: date 
    token:str 
