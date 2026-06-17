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

    room_memberships = relationship(
        "RoomMembership",
        back_populates="user",
    )


class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(80), nullable=False)
    slug = Column(String(80), unique=True, nullable=False, index=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    creator = relationship("User")

    memberships = relationship(
        "RoomMembership",
        back_populates="room",
    )

    messages = relationship(
        "Message",
        back_populates="room",
    )


class RoomMembership(Base):
    __tablename__ = "room_memberships"

    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    joined_at = Column(DateTime(timezone=True), default=utc_now)
    left_at = Column(DateTime(timezone=True), nullable=True)

    room = relationship(
        "Room",
        back_populates="memberships",
    )

    user = relationship(
        "User",
        back_populates="room_memberships",
    )


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)

    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    room_id = Column(Integer, ForeignKey("rooms.id"), nullable=True)

    message_type = Column(String(20), nullable=False)
    key_version = Column(Integer, default=1, nullable=False)

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

    room = relationship(
        "Room",
        back_populates="messages",
    )


class ConversationKey(Base):
    __tablename__ = "conversation_keys"

    id = Column(Integer, primary_key=True, index=True)

    key_scope = Column(String(20), nullable=False)
    room_id = Column(Integer, ForeignKey("rooms.id"), nullable=True)
    user_a_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user_b_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    key_version = Column(Integer, default=1, nullable=False)

    key_value = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(50), nullable=False)
    success = Column(Boolean, default=False)
    reason = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utc_now)
