from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, JSON, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Organisation(Base):
    __tablename__ = 'organisation'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    status = Column(Integer, default=0, nullable=False)
    personal = Column(Boolean, default=False, nullable=True)
    settings = Column(JSON, default={}, nullable=True)
    created_at = Column(BigInteger, nullable=True)
    updated_at = Column(BigInteger, nullable=True)


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    profile = Column(JSON, default={}, nullable=False)
    status = Column(Integer, default=0, nullable=False)
    settings = Column(JSON, default={}, nullable=True)
    created_at = Column(BigInteger, nullable=True)
    updated_at = Column(BigInteger, nullable=True)


class Role(Base):
    __tablename__ = 'role'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    org_id = Column(Integer, ForeignKey('organisation.id', ondelete='CASCADE'), nullable=False)


class Member(Base):
    __tablename__ = 'member'

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey('organisation.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    role_id = Column(Integer, ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    status = Column(Integer, nullable=False, default=0)
    settings = Column(JSON, default={}, nullable=True)
    created_at = Column(BigInteger, nullable=True)
    updated_at = Column(BigInteger, nullable=True)
