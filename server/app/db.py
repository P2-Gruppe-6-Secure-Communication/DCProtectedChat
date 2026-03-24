import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# Accept a full DATABASE_URL (e.g. from Render) or build from individual vars.
# Render sets DATABASE_URL with the postgres:// scheme; SQLAlchemy 2.x requires
# postgresql+psycopg://, so we normalise it here.
_DATABASE_URL = os.getenv("DATABASE_URL")
if _DATABASE_URL:
    # Normalise Render's URL to use psycopg3 driver.
    # Render may supply either "postgres://" or "postgresql://" — handle both.
    _DATABASE_URL = _DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    _DATABASE_URL = _DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
else:
    DB_USER = os.getenv("P2_DB_USER", "p2")
    DB_PASS = os.getenv("P2_DB_PASS", "p2password")
    DB_HOST = os.getenv("P2_DB_HOST", "127.0.0.1")
    DB_PORT = os.getenv("P2_DB_PORT", "5432")
    DB_NAME = os.getenv("P2_DB_NAME", "p2chat")
    _DATABASE_URL = f"postgresql+psycopg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

DATABASE_URL = _DATABASE_URL

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass
