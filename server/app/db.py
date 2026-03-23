import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# Adjust if you changed docker-compose creds
DB_USER = os.getenv("P2_DB_USER", "p2")
DB_PASS = os.getenv("P2_DB_PASS", "p2password")
DB_HOST = os.getenv("P2_DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("P2_DB_PORT", "5432")
DB_NAME = os.getenv("P2_DB_NAME", "p2chat")

DATABASE_URL = f"postgresql+psycopg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass