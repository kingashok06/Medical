from pydantic import BaseModel, EmailStr, constr


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None

# Define the updated ChangePasswordRequest model


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: constr(min_length=8)
    confirm_password: constr(min_length=8)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str
    confirm_password: str
    reset_token: str
