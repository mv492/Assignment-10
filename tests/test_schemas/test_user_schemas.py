import pytest
from pydantic import ValidationError
from builtins import str
from datetime import datetime
from app.schemas.user_schemas import (
    UserBase, UserCreate, UserUpdate, UserResponse, UserListResponse, LoginRequest,
    _existing_emails, _existing_nicknames
)
# A fixture providing the base set of user data (without the nickname field)
@pytest.fixture
def base_user_data():
    return {
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "Experienced developer.",
        "profile_picture_url": "https://example.com/profiles/john.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe"
    }
# Tests for UserBase
def test_user_base_valid(user_base_data):
    user = UserBase(**user_base_data)
    assert user.nickname == user_base_data["nickname"]
    assert user.email == user_base_data["email"]

# Tests for UserCreate
def test_user_create_valid(user_create_data):
    user = UserCreate(**user_create_data)
    assert user.nickname == user_create_data["nickname"]
    assert user.password == user_create_data["password"]

# Tests for UserUpdate
def test_user_update_valid(user_update_data):
    user_update = UserUpdate(**user_update_data)
    assert user_update.email == user_update_data["email"]
    assert user_update.first_name == user_update_data["first_name"]

# Tests for UserResponse
def test_user_response_valid(user_response_data):
    user = UserResponse(**user_response_data)
    assert user.id == user_response_data["id"]
    # assert user.last_login_at == user_response_data["last_login_at"]

# Tests for LoginRequest
def test_login_request_valid(login_request_data):
    login = LoginRequest(**login_request_data)
    assert login.email == login_request_data["email"]
    assert login.password == login_request_data["password"]

# Parametrized tests for nickname and email validation
@pytest.mark.parametrize("nickname", ["test_user", "test-user", "testuser123", "123test"])
def test_user_base_nickname_valid(nickname, user_base_data):
    user_base_data["nickname"] = nickname
    user = UserBase(**user_base_data)
    assert user.nickname == nickname

@pytest.mark.parametrize("nickname", ["test user", "test?user", "", "us"])
def test_user_base_nickname_invalid(nickname, user_base_data):
    user_base_data["nickname"] = nickname
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Parametrized tests for URL validation
@pytest.mark.parametrize("url", ["http://valid.com/profile.jpg", "https://valid.com/profile.png", None])
def test_user_base_url_valid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    user = UserBase(**user_base_data)
    assert user.profile_picture_url == url

@pytest.mark.parametrize("url", ["ftp://invalid.com/profile.jpg", "http//invalid", "https//invalid"])
def test_user_base_url_invalid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Tests for UserBase
def test_user_base_invalid_email(user_base_data_invalid):
    with pytest.raises(ValidationError) as exc_info:
        user = UserBase(**user_base_data_invalid)
    
    assert "value is not a valid email address" in str(exc_info.value)
    assert "john.doe.example.com" in str(exc_info.value)

# Test: When no nickname is provided, the default factory should generate one automatically.
def test_default_nickname_generated(base_user_data):
    # Remove nickname key if present
    data = base_user_data.copy()
    data.pop("nickname", None)
    
    user = UserBase(**data)
    assert user.nickname is not None, "The default nickname should not be None."
    assert len(user.nickname) >= 3, "The default nickname should have at least 3 characters."

# Parametrized test for valid nicknames that should pass the validation.
@pytest.mark.parametrize("nickname", [
    "validNick",  # simple alphanumeric
    "test_user",  # underscore allowed
    "user-123",   # dash allowed
    "ABC"         # exactly 3 characters, all letters
])
def test_valid_nicknames(base_user_data, nickname):
    data = base_user_data.copy()
    data["nickname"] = nickname
    user = UserBase(**data)
    # If no exception is raised, the nickname is valid.
    assert user.nickname == nickname

# Parametrized test for invalid nicknames that should raise a ValidationError.
@pytest.mark.parametrize("nickname", [
    "invalid nick",   # contains a space
    "test@user",      # contains a disallowed character (@)
    "ab",             # less than 3 characters
    ""                # empty string
])
def test_invalid_nicknames(base_user_data, nickname):
    data = base_user_data.copy()
    data["nickname"] = nickname
    with pytest.raises(ValidationError):
        UserBase(**data)

@pytest.mark.parametrize("nickname, invalid_char", [
    ("user#name", "#"),
    ("user$name", "$"),
    ("user^name", "^"),
    ("user&name", "&"),
    ("user name", " ")  # spaces are not allowed
])
def test_special_characters_in_nickname_invalid(nickname, invalid_char, base_user_data):
    data = base_user_data.copy()
    data["nickname"] = nickname
    with pytest.raises(ValidationError) as exc_info:
        UserBase(**data)
    # Ensure the error message contains the invalid character.
    assert invalid_char in str(exc_info.value)

# Test cases for valid nicknames that include only allowed characters.
@pytest.mark.parametrize("nickname", [
    "user_name",   # underscore allowed
    "user-name",   # dash allowed
    "username123"  # simple alphanumeric nickname
])
def test_special_characters_in_nickname_valid(nickname, base_user_data):
    data = base_user_data.copy()
    data["nickname"] = nickname
    user = UserBase(**data)
    assert user.nickname == nickname

@pytest.mark.parametrize("nickname", [
    "abc",                 # Minimum valid length: 3 characters.
    "validNickname",       # Normal valid length.
    "abcdefghijklmnopqrst" # Exactly 20 characters.
])
def test_nickname_length_valid(nickname, base_user_data):
    data = base_user_data.copy()
    data["nickname"] = nickname
    user = UserBase(**data)
    assert user.nickname == nickname

# Test nickname too short (less than 3 characters).
@pytest.mark.parametrize("nickname", [
    "ab",  # 2 characters only.
    ""     # Empty string.
])
def test_nickname_length_too_short(nickname, base_user_data):
    data = base_user_data.copy()
    data["nickname"] = nickname
    with pytest.raises(ValidationError) as exc_info:
        UserBase(**data)
    assert "at least 3 characters" in str(exc_info.value)

# Test nickname too long (more than 20 characters).
@pytest.mark.parametrize("nickname", [
    "abcdefghijklmnopqrstu",  # 21 characters.
    "thisnicknameiswaytoolongtobevalid"  # Exceeds the max length.
])
def test_nickname_length_too_long(nickname, base_user_data):
    data = base_user_data.copy()
    data["nickname"] = nickname
    with pytest.raises(ValidationError) as exc_info:
        UserBase(**data)
    assert "no more than 20 characters" in str(exc_info.value)

def test_valid_password(user_create_data):
    user = UserCreate(**user_create_data)
    assert user.password == user_create_data["password"]

# Test for passwords that are too short.
@pytest.mark.parametrize("password", [
    "S*1a",       # Less than 8 characters.
    "Ab1!"        # Only 4 characters.
])
def test_password_too_short(user_create_data, password):
    data = user_create_data.copy()
    data["password"] = password
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    assert "at least 8 characters" in str(exc_info.value)

# Test for passwords missing an uppercase letter.
@pytest.mark.parametrize("password", [
    "secure*1234",  # No uppercase letters.
])
def test_password_missing_uppercase(user_create_data, password):
    data = user_create_data.copy()
    data["password"] = password
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    assert "at least one uppercase letter" in str(exc_info.value)

# Test for passwords missing a lowercase letter.
@pytest.mark.parametrize("password", [
    "SECURE*1234",  # No lowercase letters.
])
def test_password_missing_lowercase(user_create_data, password):
    data = user_create_data.copy()
    data["password"] = password
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    assert "at least one lowercase letter" in str(exc_info.value)

# Test for passwords missing a digit.
@pytest.mark.parametrize("password", [
    "Secure*abcd",  # No digits.
])
def test_password_missing_digit(user_create_data, password):
    data = user_create_data.copy()
    data["password"] = password
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    assert "at least one number" in str(exc_info.value)

# Test for passwords missing a special character.
@pytest.mark.parametrize("password", [
    "Secure1234",  # No special characters.
])
def test_password_missing_special(user_create_data, password):
    data = user_create_data.copy()
    data["password"] = password
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    assert "at least one special character" in str(exc_info.value)

@pytest.fixture(autouse=True)
def reset_uniqueness():
    _existing_emails.clear()
    _existing_nicknames.clear()

# Tests for UserBase
def test_user_base_valid(user_base_data):
    user = UserBase(**user_base_data)
    assert user.nickname == user_base_data["nickname"]
    assert user.email == user_base_data["email"]

# Tests for UserCreate
def test_user_create_valid(user_create_data):
    user = UserCreate(**user_create_data)
    assert user.nickname == user_create_data["nickname"]
    assert user.password == user_create_data["password"]

# Tests for uniqueness: Duplicate email should fail.
def test_unique_email(user_create_data):
    # Create the first user.
    UserCreate(**user_create_data)
    # Attempt to create a second user with the same email.
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**user_create_data)
    assert "Email already exists" in str(exc_info.value)

# Tests for uniqueness: Duplicate nickname should fail.
def test_unique_nickname(user_create_data):
    # Create the first user.
    UserCreate(**user_create_data)
    # Create a new user with a different email but same nickname.
    new_data = user_create_data.copy()
    new_data["email"] = "different@example.com"
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**new_data)
    assert "Nickname already exists" in str(exc_info.value)

# Tests for UserUpdate
def test_user_update_valid(user_update_data):
    user_update = UserUpdate(**user_update_data)
    assert user_update.email == user_update_data["email"]
    assert user_update.first_name == user_update_data["first_name"]

# Tests for UserResponse
def test_user_response_valid(user_response_data):
    user = UserResponse(**user_response_data)
    assert user.id == user_response_data["id"]

# Tests for LoginRequest
def test_login_request_valid(login_request_data):
    login = LoginRequest(**login_request_data)
    assert login.email == login_request_data["email"]
    assert login.password == login_request_data["password"]
