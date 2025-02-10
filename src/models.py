from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import String, DateTime, create_engine, Integer, ForeignKey
from sqlalchemy.orm import mapped_column, Mapped, DeclarativeBase

engine = create_engine("sqlite:///sqlite.db")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    totp_secret: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.now(timezone.utc),
        onupdate=datetime.now(timezone.utc),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    jti: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


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


class UserSchema(BaseModel):
    username: str


class UserSchemaWithSecret(BaseModel):
    username: str
    totp_secret: str


class RefreshTokenSchema(BaseModel):
    refresh_token: str
