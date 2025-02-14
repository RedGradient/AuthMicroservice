import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional, AsyncGenerator, Any, Generator

import bcrypt
import jwt
import pyotp
from fastapi import FastAPI, HTTPException
from fastapi.params import Depends
from sqlalchemy.orm import Session, sessionmaker
from starlette import status
from starlette.status import HTTP_201_CREATED, HTTP_200_OK, HTTP_401_UNAUTHORIZED

from src import models
from src.models import UserSignupForm, UserAuthForm, Token, UserSchemaWithSecret, RefreshTokenSchema, engine

ALGORITHM: str = "RS256"
KEYS_DIR_PATH: Path = Path("keys")
PUBLIC_KEYS_PATH: Path = KEYS_DIR_PATH / "public_keys.json"
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


SECRET_KEY: str
key_id_store: dict[str, Any]
def get_public_key_ids() -> dict[str, Any]:
    with open(PUBLIC_KEYS_PATH, "r") as f:
        return json.load(f)  # type: ignore


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    models.init_db()

    global key_id_store
    global SECRET_KEY

    key_id_store = get_public_key_ids()

    private_key_path = KEYS_DIR_PATH / f"{key_id_store["active_key"]}.pem"
    with open(private_key_path, "r") as f:
        SECRET_KEY = f.read()

    yield

app = FastAPI(lifespan=lifespan)


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
    password_hash = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
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
def refresh(token: RefreshTokenSchema, db: Annotated[Session, Depends(get_db)]) -> Token:
    payload = verify_token(token.refresh_token)

    # Check if token is refresh token
    if ("type" not in payload) or (payload["type"] != "refresh"):
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

@app.post("/public-keys")
async def get_public_keys_() -> dict[str, Any]:
    id_key_mapping: dict[str, str] = {}
    for key_dict in key_id_store["keys"]:
        # key_dict is a dictionary with fields: 'id', 'created_at'
        key_id = key_dict["id"]
        id_key_mapping[key_id] = open(f"{KEYS_DIR_PATH}/{key_id}.pub.pem").read()

    return id_key_mapping


def create_access_token(email: str) -> str:
    headers = { "kid": key_id_store["active_key"]}
    payload = {
        "sub": email,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    return jwt.encode(payload, SECRET_KEY, ALGORITHM, headers=headers)

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
    headers = { "kid": key_id_store["active_key"]}
    payload = {
        "sub": email,
        "jti": jti,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    refresh_token = jwt.encode(payload, SECRET_KEY, ALGORITHM, headers=headers)

    # Save refresh token to DB
    user = get_user_by_email(email, db)
    refresh_token_model = models.RefreshToken(user_id=user.id, jti=jti)
    db.add(refresh_token_model)
    db.commit()

    return refresh_token


def verify_token(token: str) -> dict[str, str]:
    try:

        unverified_header = jwt.get_unverified_header(token)
        key_id = unverified_header["kid"]

        key_path = f"{KEYS_DIR_PATH}/{key_id}.pub.pem"
        with open(key_path, "r") as f:
            public_key = f.read()
        payload: dict[str, str] = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.PyJWTError as e:
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
    if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        raise HTTPException(status_code=401, detail=f"Incorrect password")
    return user