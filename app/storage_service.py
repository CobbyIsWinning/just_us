from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session, joinedload

from app.models import ConversationKey, Message


@dataclass
class StoredMessageRecord:
    id: int
    sender: str
    recipient: str | None
    room: str | None
    message_type: str
    key_version: int
    ciphertext: str
    nonce: str
    hmac_digest: str
    replay_token: str
    created_at: datetime


@dataclass
class StoredKeyRecord:
    id: int
    key_scope: str
    room_id: int | None
    user_a_id: int | None
    user_b_id: int | None
    key_version: int
    protected_key_value: str
    created_at: datetime


def get_stored_messages(
    db: Session,
) -> list[StoredMessageRecord]:
    messages = (
        db.query(Message)
        .options(
            joinedload(Message.sender),
            joinedload(Message.recipient),
            joinedload(Message.room),
        )
        .order_by(Message.created_at.desc())
        .all()
    )

    return [
        StoredMessageRecord(
            id=message.id,
            sender=message.sender.username,
            recipient=(
                message.recipient.username
                if message.recipient
                else None
            ),
            room=(
                message.room.slug
                if message.room
                else None
            ),
            message_type=message.message_type,
            key_version=message.key_version,
            ciphertext=message.ciphertext,
            nonce=message.nonce,
            hmac_digest=message.hmac_digest,
            replay_token=message.replay_token,
            created_at=message.created_at,
        )
        for message in messages
    ]


def get_stored_keys(
    db: Session,
) -> list[StoredKeyRecord]:
    key_records = (
        db.query(ConversationKey)
        .order_by(ConversationKey.created_at.desc())
        .all()
    )

    return [
        StoredKeyRecord(
            id=record.id,
            key_scope=record.key_scope,
            room_id=record.room_id,
            user_a_id=record.user_a_id,
            user_b_id=record.user_b_id,
            key_version=record.key_version,
            protected_key_value=record.key_value,
            created_at=record.created_at,
        )
        for record in key_records
    ]
