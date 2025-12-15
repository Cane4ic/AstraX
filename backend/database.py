import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL")  # Render подставит сюда свой URL

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,  # предотвращает обрыв соединения
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
