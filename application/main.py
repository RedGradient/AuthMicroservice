import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Generator, Annotated, Optional, Sequence

import jwt
import sqlalchemy
from fastapi import FastAPI, HTTPException
from fastapi.params import Depends
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from starlette import status
from starlette.requests import Request
from starlette.status import HTTP_201_CREATED, HTTP_200_OK

from application import models

app = FastAPI()

SECRET_KEY = "6d20267ad3f1e33acf4bb417fb7388cab6dba4e6809c6318baf341cef09fdedf"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
engine = create_engine("sqlite:///sqlite.db", echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class UserSignupForm(BaseModel):
    username: str
    email: str
    password: str


class UserAuthForm(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str


class RefreshToken(BaseModel):
    refresh_token: str


class UserSchema(BaseModel):
    username: str


async def jwt_auth(request: Request) -> None:
    # Check if there is an Authentication header
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Authorization required"
        )

    # Validate token
    jwt_token = authorization_header.split()[-1]
    payload = verify_token(jwt_token)
    if payload["type"] != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


@app.post(
    "/signup",
    status_code=HTTP_201_CREATED,
    response_model=UserSchema,
    summary="User registration",
    description="Creates a new user account. Provided email and username must be unique",
)
async def signup(user: UserSignupForm, db: Annotated[Session, Depends(get_db)]) -> models.User:
    # Check if user already exists
    if db.query(models.User).where(models.User.email.is_(user.email)).first():
        raise HTTPException(status_code=400, detail=f"User with email {user.email} already exists")
    if db.query(models.User).where(models.User.username.is_(user.username)).first():
        raise HTTPException(status_code=400, detail=f"User with username {user.username} already exists")

    # Create user from given data
    password_hash = pwd_context.hash(user.password)
    new_user = models.User(
        username=user.username, email=user.email, password_hash=password_hash
    )
    db.add(new_user)
    db.commit()
    return new_user


@app.post(
    "/token",
    status_code=HTTP_200_OK,
    response_model=Token,
    summary="Get access and refresh tokens",
    description="Authenticates a user using email and password. If successful, returns access and refresh tokens",
)
async def get_token(user_login: UserAuthForm, db: Annotated[Session, Depends(get_db)]) -> Any:
    authenticate_user(user_login.email, user_login.password, db)

    return Token(
        access_token=create_access_token(user_login.email),
        refresh_token=create_refresh_token(user_login.email, db),
    )


@app.post(
    "/refresh",
    status_code=HTTP_200_OK,
    response_model=Token,
    summary="Get new access and refresh tokens",
    description="Uses a valid refresh token to generate a new access and refresh tokens",
)
def refresh(token: RefreshToken, db: Annotated[Session, Depends(get_db)]) -> Token:
    payload = verify_token(token.refresh_token)

    # Check if token is refresh token
    if ("type" not in payload) or (payload["type"] != "refresh_token"):
        raise HTTPException(status_code=401, detail="Invalid token")

    # Check if refresh token is in database
    old_jti = payload["jti"]
    existing_token = (
        db.query(models.RefreshToken)
        .where(models.RefreshToken.jti.is_(old_jti))
        .first()
    )
    if existing_token is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    email = payload["sub"]

    return Token(
        access_token=create_access_token(email),
        refresh_token=create_refresh_token(email, db),
    )


@app.get(
    "/users",
    status_code=HTTP_200_OK,
    response_model=list[UserSchema],
    dependencies=[Depends(jwt_auth)],
    summary="Get all users",
    description="Returns a list of all users from the database. Authentication with a JWT token is required",
)
async def get_users(db: Annotated[Session, Depends(get_db)]) -> Sequence[models.User]:
    users = db.scalars(sqlalchemy.select(models.User)).all()
    return users


def create_access_token(email: str) -> str:
    data = {
        "sub": email,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    return jwt.encode(data, SECRET_KEY, ALGORITHM)


def create_refresh_token(email: str, db: Session) -> str:
    # Remove old refresh token
    user = get_user_by_email(email, db)
    old_refresh_token = (
        db.query(models.RefreshToken)
        .where(models.RefreshToken.user_id.is_(user.id))
        .first()
    )
    if old_refresh_token:
        db.delete(old_refresh_token)
        db.commit()

    # Create refresh token
    jti = str(uuid.uuid4())
    data = {
        "sub": email,
        "jti": jti,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    refresh_token = jwt.encode(data, SECRET_KEY, ALGORITHM)

    # Save refresh token to DB
    user = get_user_by_email(email, db)
    refresh_token_model = models.RefreshToken(user_id=user.id, jti=jti)
    db.add(refresh_token_model)
    db.commit()

    return refresh_token


def verify_token(token: str) -> dict[str, str]:
    try:
        payload: dict[str, str] = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


def get_user_by_email(email: str, db: Session) -> models.User:
    # Check if user exists
    user: Optional[models.User] = (
        db.query(models.User).where(models.User.email.is_(email)).first()
    )
    if not user:
        raise HTTPException(
            status_code=400, detail=f"User with email {email} is not exist"
        )

    return user


def authenticate_user(email: str, password: str, db: Session) -> None:
    user = get_user_by_email(email, db)
    if not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail=f"Incorrect password")
