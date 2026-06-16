from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    failed_login_attempts = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    sent_messages = relationship(
        "Message",
        foreign_keys="Message.sender_id",
        back_populates="sender",
    )

    received_messages = relationship(
        "Message",
        foreign_keys="Message.recipient_id",
        back_populates="recipient",
    )


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)

    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    message_type = Column(String(20), nullable=False)

    ciphertext = Column(Text, nullable=False)
    nonce = Column(Text, nullable=False)
    hmac_digest = Column(Text, nullable=False)

    replay_token = Column(String(100), unique=True, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now)

    sender = relationship(
        "User",
        foreign_keys=[sender_id],
        back_populates="sent_messages",
    )

    recipient = relationship(
        "User",
        foreign_keys=[recipient_id],
        back_populates="received_messages",
    )


class ConversationKey(Base):
    __tablename__ = "conversation_keys"

    id = Column(Integer, primary_key=True, index=True)

    key_scope = Column(String(20), nullable=False)
    user_a_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user_b_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    key_value = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(50), nullable=False)
    success = Column(Boolean, default=False)
    reason = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utc_now)