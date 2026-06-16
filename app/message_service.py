import logging
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.crypto_utils import (
    EncryptedMessage,
    IntegrityError,
    KeyProtectionError,
    decrypt_message,
    encrypt_message,
    generate_message_keys,
    protect_message_keys,
    recover_message_keys,
)
from app.models import ConversationKey, Message, User


ROOM_KEY_SCOPE = "room"


@dataclass
class DisplayMessage:
    id: int
    sender: str
    content: str
    message_type: str
    recipient: str | None
    created_at: object
    integrity_verified: bool


def get_or_create_room_keys(db: Session):
    room_key_record = (
        db.query(ConversationKey)
        .filter(
            ConversationKey.key_scope == ROOM_KEY_SCOPE,
            ConversationKey.user_a_id.is_(None),
            ConversationKey.user_b_id.is_(None),
        )
        .first()
    )

    if room_key_record:
        return recover_message_keys(room_key_record.key_value)

    message_keys = generate_message_keys()
    protected_keys = protect_message_keys(message_keys)

    room_key_record = ConversationKey(
        key_scope=ROOM_KEY_SCOPE,
        user_a_id=None,
        user_b_id=None,
        key_value=protected_keys,
    )

    db.add(room_key_record)
    db.commit()

    logging.info("Secure room encryption keys generated and stored.")

    return message_keys


def create_general_message(
    db: Session,
    sender: User,
    plaintext: str,
) -> Message:
    cleaned_message = plaintext.strip()

    if not cleaned_message:
        raise ValueError("Message cannot be empty.")

    room_keys = get_or_create_room_keys(db)

    encrypted = encrypt_message(
        plaintext=cleaned_message,
        keys=room_keys,
    )

    message = Message(
        sender_id=sender.id,
        recipient_id=None,
        message_type="general",
        ciphertext=encrypted.ciphertext,
        nonce=encrypted.nonce,
        hmac_digest=encrypted.hmac_digest,
        replay_token=str(uuid.uuid4()),
    )

    db.add(message)
    db.commit()
    db.refresh(message)

    logging.info(
        "General message encrypted and stored. Sender=%s MessageID=%s",
        sender.username,
        message.id,
    )

    return message


def get_general_messages(
    db: Session,
) -> list[DisplayMessage]:
    database_messages = (
        db.query(Message)
        .filter(Message.message_type == "general")
        .order_by(Message.created_at.asc())
        .all()
    )

    if not database_messages:
        return []

    try:
        room_keys = get_or_create_room_keys(db)
    except KeyProtectionError:
        logging.exception("Room encryption keys could not be recovered.")
        return []

    display_messages: list[DisplayMessage] = []

    for message in database_messages:
        encrypted = EncryptedMessage(
            ciphertext=message.ciphertext,
            nonce=message.nonce,
            hmac_digest=message.hmac_digest,
        )

        try:
            plaintext = decrypt_message(
                encrypted_message=encrypted,
                keys=room_keys,
            )

            display_messages.append(
                DisplayMessage(
                    id=message.id,
                    sender=message.sender.username,
                    content=plaintext,
                    message_type=message.message_type,
                    recipient=None,
                    created_at=message.created_at,
                    integrity_verified=True,
                )
            )

            logging.info(
                "General message decrypted successfully. MessageID=%s",
                message.id,
            )

        except IntegrityError:
            logging.error(
                "HMAC verification failed. Possible tampering. MessageID=%s",
                message.id,
            )

            display_messages.append(
                DisplayMessage(
                    id=message.id,
                    sender=message.sender.username,
                    content="[Message rejected: integrity verification failed]",
                    message_type=message.message_type,
                    recipient=None,
                    created_at=message.created_at,
                    integrity_verified=False,
                )
            )

        except Exception:
            logging.exception(
                "Message decryption failed. MessageID=%s",
                message.id,
            )

            display_messages.append(
                DisplayMessage(
                    id=message.id,
                    sender=message.sender.username,
                    content="[Message could not be decrypted]",
                    message_type=message.message_type,
                    recipient=None,
                    created_at=message.created_at,
                    integrity_verified=False,
                )
            )

    return display_messages
