from sqlalchemy import Column, String, Integer
from app.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    phone = Column(String, unique=True, index=True)
    cpr = Column(String, unique=True, index=True, nullable=False)
    security_answer1 = Column(String)
    security_answer2 = Column(String)