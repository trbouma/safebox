from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt

from fastapi import FastAPI, HTTPException
from app.appmodels import RegisteredSafebox
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.config import Settings

settings = Settings()
# Secret key for signing JWT
# SECRET_KEY = "foobar"
# ALGORITHM = "HS256"
engine = create_engine(settings.DATABASE)
SQLModel.metadata.create_all(engine)

# Function to generate JWT token
def create_jwt_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str):
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
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

def fetch_safebox(access_token) -> RegisteredSafebox:
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")
    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        access_key = payload.get("sub")
        if not access_key:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    print(access_key)
    # Token is valid, now get the safebox
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            handle = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{access_key} not found")
        
    return safebox_found
