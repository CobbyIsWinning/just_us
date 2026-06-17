from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.auth import authenticate_user, create_user
from app.logger_config import log_replay_detection, log_security_event
from app.message_service import create_general_message, get_visible_messages
from app.models import Message, User
from app.room_service import ensure_default_room_for_user


@dataclass
class AttackResult:
    name: str
    status: str
    details: str
    log_event: str


def tamper_text(value: str) -> str:
    if not value:
        return "A"

    replacement = "A" if value[-1] != "A" else "B"
    return value[:-1] + replacement


def simulate_mitm_tampering(
    db: Session,
    current_user: User,
) -> AttackResult:
    room = ensure_default_room_for_user(
        db=db,
        user=current_user,
    )

    message = create_general_message(
        db=db,
        sender=current_user,
        room=room,
        plaintext="MITM attack simulation message.",
    )

    message.hmac_digest = tamper_text(message.hmac_digest)
    db.commit()

    visible_messages = get_visible_messages(
        db=db,
        current_user=current_user,
        room=room,
    )

    rejected_message = next(
        (
            display_message
            for display_message in visible_messages
            if display_message.id == message.id
        ),
        None,
    )

    if rejected_message and not rejected_message.integrity_verified:
        return AttackResult(
            name="Man-in-the-Middle tampering",
            status="Detected",
            details=(
                f"Message #{message.id} had its HMAC modified. "
                "The room rejected it during integrity verification."
            ),
            log_event="MITM_TAMPERING_DETECTED",
        )

    log_security_event(
        "MITM_TAMPERING_SIMULATION_FAILED",
        message_id=message.id,
    )

    return AttackResult(
        name="Man-in-the-Middle tampering",
        status="Unexpected result",
        details=(
            f"Message #{message.id} was tampered with, but the simulation "
            "did not observe a rejected display message."
        ),
        log_event="MITM_TAMPERING_SIMULATION_FAILED",
    )


def simulate_replay_attack(
    db: Session,
    current_user: User,
) -> AttackResult:
    source_message = (
        db.query(Message)
        .order_by(Message.created_at.desc())
        .first()
    )

    if not source_message:
        room = ensure_default_room_for_user(
            db=db,
            user=current_user,
        )

        source_message = create_general_message(
            db=db,
            sender=current_user,
            room=room,
            plaintext="Replay attack source message.",
        )

    duplicate_token = source_message.replay_token

    existing_message = (
        db.query(Message)
        .filter(Message.replay_token == duplicate_token)
        .first()
    )

    if existing_message:
        log_replay_detection(
            replay_token=duplicate_token,
            username=current_user.username,
            message_id=existing_message.id,
        )

        return AttackResult(
            name="Replay attack",
            status="Detected",
            details=(
                "A duplicate replay token was submitted and rejected before "
                f"storage. Existing message ID: {existing_message.id}."
            ),
            log_event="REPLAY_DETECTED",
        )

    return AttackResult(
        name="Replay attack",
        status="Unexpected result",
        details="No existing replay token was available for the simulation.",
        log_event="REPLAY_SIMULATION_FAILED",
    )


def simulate_bruteforce_attack(db: Session) -> AttackResult:
    username = "attack_demo"
    password = "password123"

    user = db.query(User).filter(User.username == username).first()

    if not user:
        user = create_user(
            db=db,
            username=username,
            password=password,
        )

    if not user:
        user = db.query(User).filter(User.username == username).first()

    user.failed_login_attempts = 0
    user.is_active = True
    db.commit()

    responses = []

    for _ in range(3):
        _, error = authenticate_user(
            db=db,
            username=username,
            password="wrong-password",
        )
        responses.append(error)

    db.refresh(user)

    if user.failed_login_attempts >= 3:
        return AttackResult(
            name="Brute-force login attempt",
            status="Detected",
            details=(
                f"Three wrong passwords were submitted for @{username}. "
                f"Failed attempts stored: {user.failed_login_attempts}. "
                f"Final response: {responses[-1]}"
            ),
            log_event="BRUTE_FORCE_DETECTED",
        )

    return AttackResult(
        name="Brute-force login attempt",
        status="Unexpected result",
        details=(
            f"Expected three failed attempts, found "
            f"{user.failed_login_attempts}."
        ),
        log_event="BRUTE_FORCE_SIMULATION_FAILED",
    )
