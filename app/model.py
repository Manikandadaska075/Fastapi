from sqlmodel import SQLModel, Field
from typing import *

class Admin(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_first_name: Optional[str]
    user_last_name : Optional[str] 
    designation :str
    password: str
    email: str
    address: Optional[str]
    phone_number: Optional[str]
    is_active: bool = True
    is_superuser: bool = False 

class Employee(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_first_name: Optional[str]
    user_last_name : Optional[str]
    designation :Optional[str]
    email: Optional[str]
    address: Optional[str]
    phone_number: Optional[str]
    is_active: bool = True

    

