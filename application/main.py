import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Generator, Annotated, Optional, Sequence, AsyncGenerator

import jwt
import pyotp
import sqlalchemy
from fastapi import FastAPI, HTTPException
from fastapi.params import Depends
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import sessionmaker, Session
from starlette import status
from starlette.requests import Request
from starlette.status import HTTP_201_CREATED, HTTP_200_OK, HTTP_401_UNAUTHORIZED

from application import models


SECRET_KEY: str

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    models.init_db()
    with open("private_key.pem", "r") as f:
        global SECRET_KEY
        SECRET_KEY = f.read()
    yield

app = FastAPI(lifespan=lifespan)

ALGORITHM = "RS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=models.engine)


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
    totp_password: str | None = None

class Token(BaseModel):
    access_token: str
    refresh_token: str


class RefreshToken(BaseModel):
    refresh_token: str


class UserSchema(BaseModel):
    username: str

class UserSchemaWithSecret(BaseModel):
    username: str
    totp_secret: str


async def jwt_auth(request: Request) -> None:
    # Check if there is an Authentication header
    authorization_header = request.headers.get("Authorization")
    if (authorization_header is None) or (authorization_header == ""):
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
    response_model=UserSchemaWithSecret,
    summary="User registration",
    description="Creates a new user account. Provided email must be unique",
)
async def signup(user: UserSignupForm, db: Annotated[Session, Depends(get_db)]) -> models.User:
    # Check if user already exists
    if db.query(models.User).where(models.User.email.is_(user.email)).first():
        raise HTTPException(status_code=400, detail=f"User with email {user.email} already exists")

    # Generate secret key for disposable passwords
    totp_secret = pyotp.random_base32()

    # Create user in database
    password_hash = pwd_context.hash(user.password)
    new_user = models.User(
        username=user.username,
        email=user.email,
        password_hash=password_hash,
        totp_secret=totp_secret
    )
    db.add(new_user)
    db.commit()
    return new_user


@app.post(
    "/token",
    status_code=HTTP_200_OK,
    response_model=Token,
    summary="Get access and refresh tokens",
    description="Authenticates a user with email and password. If successful, returns access and refresh tokens",
)
async def get_token(user_login: UserAuthForm, db: Annotated[Session, Depends(get_db)]) -> Token:
    authenticate_user(user_login.email, user_login.password, db)

    return Token(
        access_token=create_access_token(user_login.email),
        refresh_token=create_refresh_token(user_login.email, db),
    )


@app.post(
    "/token/2fa",
    status_code=HTTP_200_OK,
    response_model=Token,
    summary="Verify 2FA and get access and refresh tokens",
    description="Authenticates a user with email, password, and TOTP code. If successful, returns access and refresh tokens",
)
async def get_token_2fa(user_login: UserAuthForm, db: Annotated[Session, Depends(get_db)]) -> Token:
    if user_login.totp_password is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="TOTP password is required")

    user = authenticate_user(user_login.email, user_login.password, db)

    # Check TOTP password
    totp_secret = user.totp_secret
    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(user_login.totp_password):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Incorrect TOTP password")

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


def authenticate_user(email: str, password: str, db: Session) -> models.User:
    user = get_user_by_email(email, db)
    if not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail=f"Incorrect password")
    return user