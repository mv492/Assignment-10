import pytest
from pydantic import ValidationError
from builtins import str
from datetime import datetime
from app.schemas.user_schemas import UserBase, UserCreate, UserUpdate, UserResponse, UserListResponse, LoginRequest

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