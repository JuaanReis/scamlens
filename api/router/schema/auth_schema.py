from pydantic import BaseModel, EmailStr, Field, field_validator
from scamLens import config

auth_config = config["auth"]

class PasswordBody(BaseModel):
    password: str = Field(min_length=1)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value.encode("utf-8")) > auth_config["max_password_bytes"]:
            raise ValueError(f"Senha excede o limite de {auth_config['max_password_bytes']} bytes")
        return value

class RegisterBody(PasswordBody):
    email: EmailStr
    name: str = Field(min_length=1, max_length=auth_config["max_name_length"])

class LoginBody(PasswordBody):
    email: EmailStr
    remember: bool = False
