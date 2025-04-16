from builtins import ValueError
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid
import re

from app.utils.nickname_gen import generate_nickname

# Global sets to simulate uniqueness.
_existing_emails = set()
_existing_nicknames = set()

class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    # Removed built-in constraints from Field.
    nickname: str = Field(default_factory=generate_nickname, example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    # URL validation for all URL fields.
    _validate_urls = validator(
        'profile_picture_url', 'linkedin_profile_url', 'github_profile_url',
        pre=True, allow_reuse=True
    )(validate_url)
    
    @validator('nickname')
    def validate_nickname(cls, value):
        if value is None:
            raise ValueError("Nickname must be provided or auto-generated.")
        if len(value) < 3:
            raise ValueError("Nickname must be at least 3 characters long.")
        if len(value) > 20:
            raise ValueError("Nickname must be no more than 20 characters long.")
        if not re.match(r'^[\w-]+$', value):
            raise ValueError("Nickname must only contain letters, numbers, underscores, or dashes.")
        return value

    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

    @validator('email')
    def validate_unique_email(cls, value):
        if value in _existing_emails:
            raise ValueError("Email already exists.")
        _existing_emails.add(value)
        return value

    @validator('nickname')
    def validate_unique_nickname(cls, value):
        if value in _existing_nicknames:
            raise ValueError("Nickname already exists.")
        _existing_nicknames.add(value)
        return value

    @validator('password')
    def validate_password(cls, value):
        # Minimum length check.
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        # Must contain at least one uppercase letter.
        if not re.search(r'[A-Z]', value):
            raise ValueError("Password must contain at least one uppercase letter.")
        # Must contain at least one lowercase letter.
        if not re.search(r'[a-z]', value):
            raise ValueError("Password must contain at least one lowercase letter.")
        # Must contain at least one digit.
        if not re.search(r'\d', value):
            raise ValueError("Password must contain at least one number.")
        # Must contain at least one special character.
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError("Password must contain at least one special character.")
        return value

class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    # Remove built-in constraints here as well.
    nickname: Optional[str] = Field(None, example="john_doe123")
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    email: EmailStr = Field(..., example="john.doe@example.com")
    # Redefine nickname; no built-in constraints.
    nickname: str = Field(default_factory=generate_nickname, example=generate_nickname())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    is_professional: Optional[bool] = Field(default=False, example=True)

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(), "nickname": generate_nickname(), "email": "john.doe@example.com",
        "first_name": "John", "last_name": "Doe", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "profile_picture_url": "https://example.com/profiles/john.jpg", 
        "linkedin_profile_url": "https://linkedin.com/in/johndoe", 
        "github_profile_url": "https://github.com/johndoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
