from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt

# Secret key for signing JWT
SECRET_KEY = "foobar"
ALGORITHM = "HS256"

# Function to generate JWT token
def create_jwt_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_token
    except jwt.ExpiredSignatureError:
        return "Token has expired"
    except jwt.InvalidTokenError:
        return "Invalid token"

# Example Login Function
def authenticate_user(username: str, password: str):
    # Mock user authentication
    if username == "user" and password == "password":
        return {"username": username}
    return None