from pydantic import BaseModel, EmailStr


class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    document: str
    password: str


class LoginRequest(BaseModel):
    login: EmailStr
    password: str


class RecuperarSenhaRequest(BaseModel):
    document: str
    email: EmailStr
    new_password: str


class TokenResponse(BaseModel):
    token: str


class MessageResponse(BaseModel):
    message: str


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    document: str
    password: str
