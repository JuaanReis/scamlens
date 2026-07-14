from pydantic import BaseModel, EmailStr

class RegisterBody(BaseModel):
    email: EmailStr
    name: str
    password: str

class LoginBody(BaseModel):
    email: EmailStr
    password: str
    remember: bool = False