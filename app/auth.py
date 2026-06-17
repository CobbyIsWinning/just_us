import bcrypt
import logging
from sqlalchemy.orm import Session

from app.logger_config import log_security_event
from app.models import LoginAttempt, User

MAX_FAILED_ATTEMPTS = 3


def hash_password(password: str) -> str:
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    )
    return hashed_password.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8"),
    )


def get_user_by_username(db: Session, username: str) -> User | None:
    return (
        db.query(User)
        .filter(User.username == username)
        .first()
    )


def create_user(
    db: Session,
    username: str,
    password: str,
) -> User | None:
    if get_user_by_username(db, username):
        return None

    user = User(
        username=username,
        password_hash=hash_password(password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def record_login_attempt(
    db: Session,
    username: str,
    success: bool,
    reason: str,
) -> None:
    attempt = LoginAttempt(
        username=username,
        success=success,
        reason=reason,
    )

    db.add(attempt)
    db.commit()


def authenticate_user(
    db: Session,
    username: str,
    password: str,
) -> tuple[User | None, str | None]:
    user = get_user_by_username(db, username)

    if not user:
        record_login_attempt(
            db,
            username,
            False,
            "User does not exist",
        )
        log_security_event(
            "LOGIN_FAILURE",
            level=logging.WARNING,
            username=username,
            reason="User does not exist",
        )
        return None, "Invalid username or password."

    if not user.is_active:
        record_login_attempt(
            db,
            username,
            False,
            "Inactive account",
        )
        log_security_event(
            "LOGIN_FAILURE",
            level=logging.WARNING,
            username=username,
            reason="Inactive account",
        )
        return None, "This account is inactive."

    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        record_login_attempt(
            db,
            username,
            False,
            "Account blocked after repeated failures",
        )
        log_security_event(
            "BRUTE_FORCE_DETECTED",
            level=logging.WARNING,
            username=username,
            failed_attempts=user.failed_login_attempts,
            action="blocked_login_rejected",
        )
        return None, "Account temporarily blocked."

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1
        db.commit()

        record_login_attempt(
            db,
            username,
            False,
            "Incorrect password",
        )

        remaining_attempts = MAX_FAILED_ATTEMPTS - user.failed_login_attempts

        log_security_event(
            "LOGIN_FAILURE",
            level=logging.WARNING,
            username=username,
            reason="Incorrect password",
            failed_attempts=user.failed_login_attempts,
            attempts_remaining=max(remaining_attempts, 0),
        )

        if remaining_attempts <= 0:
            log_security_event(
                "BRUTE_FORCE_DETECTED",
                level=logging.WARNING,
                username=username,
                failed_attempts=user.failed_login_attempts,
                action="account_temporarily_blocked",
            )
            return None, "Account temporarily blocked."

        return (
            None,
            f"Invalid username or password. "
            f"Attempts remaining: {remaining_attempts}",
        )

    user.failed_login_attempts = 0
    db.commit()

    record_login_attempt(
        db,
        username,
        True,
        "Login successful",
    )

    log_security_event(
        "LOGIN_SUCCESS",
        username=username,
        user_id=user.id,
    )

    return user, None
