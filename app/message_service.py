import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import or_
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
from app.logger_config import log_security_event
from app.models import ConversationKey, Message, User


ROOM_KEY_SCOPE = "room"
PRIVATE_KEY_SCOPE = "private"


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

    log_security_event(
        "ROOM_KEY_CREATED",
        key_scope=ROOM_KEY_SCOPE,
        key_record_id=room_key_record.id,
    )

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

    log_security_event(
        "GENERAL_MESSAGE_ENCRYPTED",
        sender=sender.username,
        sender_id=sender.id,
        message_id=message.id,
        replay_token=message.replay_token,
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
        log_security_event(
            "KEY_RECOVERY_FAILURE",
            level=logging.ERROR,
            key_scope=ROOM_KEY_SCOPE,
        )
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

            log_security_event(
                "HMAC_VERIFICATION_SUCCESS",
                message_id=message.id,
                message_type=message.message_type,
            )

            log_security_event(
                "MESSAGE_DECRYPTED",
                message_id=message.id,
                message_type=message.message_type,
                viewer="room",
            )

        except IntegrityError:
            log_security_event(
                "HMAC_VERIFICATION_FAILURE",
                level=logging.ERROR,
                message_id=message.id,
                message_type=message.message_type,
                action="message_rejected",
            )

            log_security_event(
                "MITM_TAMPERING_DETECTED",
                level=logging.ERROR,
                message_id=message.id,
                message_type=message.message_type,
                action="message_rejected",
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
            log_security_event(
                "MESSAGE_DECRYPTION_FAILURE",
                level=logging.ERROR,
                message_id=message.id,
                message_type=message.message_type,
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


def normalize_user_pair(
    user_a_id: int,
    user_b_id: int,
) -> tuple[int, int]:
    """
    Always store the smaller user ID first.

    This prevents duplicate keys such as alice_bob and bob_alice.
    """
    return tuple(sorted((user_a_id, user_b_id)))


def get_or_create_private_keys(
    db: Session,
    user_a: User,
    user_b: User,
):
    first_user_id, second_user_id = normalize_user_pair(
        user_a.id,
        user_b.id,
    )

    key_record = (
        db.query(ConversationKey)
        .filter(
            ConversationKey.key_scope == PRIVATE_KEY_SCOPE,
            ConversationKey.user_a_id == first_user_id,
            ConversationKey.user_b_id == second_user_id,
        )
        .first()
    )

    if key_record:
        return recover_message_keys(key_record.key_value)

    message_keys = generate_message_keys()
    protected_keys = protect_message_keys(message_keys)

    key_record = ConversationKey(
        key_scope=PRIVATE_KEY_SCOPE,
        user_a_id=first_user_id,
        user_b_id=second_user_id,
        key_value=protected_keys,
    )

    db.add(key_record)
    db.commit()

    log_security_event(
        "PRIVATE_HANDSHAKE_CREATED",
        user_a=user_a.username,
        user_b=user_b.username,
        user_a_id=user_a.id,
        user_b_id=user_b.id,
    )

    log_security_event(
        "PRIVATE_KEY_CREATED",
        key_record_id=key_record.id,
        user_a=user_a.username,
        user_b=user_b.username,
        user_a_id=first_user_id,
        user_b_id=second_user_id,
    )

    return message_keys


def create_private_message(
    db: Session,
    sender: User,
    recipient: User,
    plaintext: str,
) -> Message:
    cleaned_message = plaintext.strip()

    if not cleaned_message:
        raise ValueError("Private message cannot be empty.")

    if sender.id == recipient.id:
        raise ValueError(
            "You cannot send a private message to yourself."
        )

    private_keys = get_or_create_private_keys(
        db=db,
        user_a=sender,
        user_b=recipient,
    )

    encrypted = encrypt_message(
        plaintext=cleaned_message,
        keys=private_keys,
    )

    message = Message(
        sender_id=sender.id,
        recipient_id=recipient.id,
        message_type="private",
        ciphertext=encrypted.ciphertext,
        nonce=encrypted.nonce,
        hmac_digest=encrypted.hmac_digest,
        replay_token=str(uuid.uuid4()),
    )

    db.add(message)
    db.commit()
    db.refresh(message)

    log_security_event(
        "PRIVATE_MESSAGE_ENCRYPTED",
        sender=sender.username,
        recipient=recipient.username,
        sender_id=sender.id,
        recipient_id=recipient.id,
        message_id=message.id,
        replay_token=message.replay_token,
    )

    return message


def get_private_messages_for_user(
    db: Session,
    current_user: User,
) -> list[DisplayMessage]:
    database_messages = (
        db.query(Message)
        .filter(
            Message.message_type == "private",
            or_(
                Message.sender_id == current_user.id,
                Message.recipient_id == current_user.id,
            ),
        )
        .order_by(Message.created_at.asc())
        .all()
    )

    display_messages: list[DisplayMessage] = []

    for message in database_messages:
        if not message.recipient:
            log_security_event(
                "PRIVATE_MESSAGE_RECIPIENT_MISSING",
                level=logging.ERROR,
                message_id=message.id,
            )
            continue

        try:
            private_keys = get_or_create_private_keys(
                db=db,
                user_a=message.sender,
                user_b=message.recipient,
            )

            encrypted = EncryptedMessage(
                ciphertext=message.ciphertext,
                nonce=message.nonce,
                hmac_digest=message.hmac_digest,
            )

            plaintext = decrypt_message(
                encrypted_message=encrypted,
                keys=private_keys,
            )

            display_messages.append(
                DisplayMessage(
                    id=message.id,
                    sender=message.sender.username,
                    content=plaintext,
                    message_type="private",
                    recipient=message.recipient.username,
                    created_at=message.created_at,
                    integrity_verified=True,
                )
            )

            log_security_event(
                "HMAC_VERIFICATION_SUCCESS",
                message_id=message.id,
                message_type=message.message_type,
                viewer=current_user.username,
            )

            log_security_event(
                "MESSAGE_DECRYPTED",
                message_id=message.id,
                message_type=message.message_type,
                viewer=current_user.username,
            )

        except IntegrityError:
            log_security_event(
                "HMAC_VERIFICATION_FAILURE",
                level=logging.ERROR,
                message_id=message.id,
                message_type=message.message_type,
                viewer=current_user.username,
                action="message_rejected",
            )

            log_security_event(
                "MITM_TAMPERING_DETECTED",
                level=logging.ERROR,
                message_id=message.id,
                message_type=message.message_type,
                viewer=current_user.username,
                action="message_rejected",
            )

            display_messages.append(
                DisplayMessage(
                    id=message.id,
                    sender=message.sender.username,
                    content=(
                        "[Private message rejected: "
                        "integrity verification failed]"
                    ),
                    message_type="private",
                    recipient=message.recipient.username,
                    created_at=message.created_at,
                    integrity_verified=False,
                )
            )

        except Exception:
            logging.exception(
                "Private message decryption failed. "
                "Viewer=%s MessageID=%s",
                current_user.username,
                message.id,
            )
            log_security_event(
                "MESSAGE_DECRYPTION_FAILURE",
                level=logging.ERROR,
                message_id=message.id,
                message_type=message.message_type,
                viewer=current_user.username,
            )

            display_messages.append(
                DisplayMessage(
                    id=message.id,
                    sender=message.sender.username,
                    content="[Private message could not be decrypted]",
                    message_type="private",
                    recipient=message.recipient.username,
                    created_at=message.created_at,
                    integrity_verified=False,
                )
            )

    return display_messages


def get_visible_messages(
    db: Session,
    current_user: User,
) -> list[DisplayMessage]:
    messages = []

    messages.extend(
        get_general_messages(db)
    )

    messages.extend(
        get_private_messages_for_user(
            db=db,
            current_user=current_user,
        )
    )

    messages.sort(
        key=lambda message: message.created_at
    )

    return messages
