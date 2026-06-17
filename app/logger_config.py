import logging
import os
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


SECURITY_LOG_PATH = os.getenv(
    "SECURITY_LOG_PATH",
    "/tmp/just_us_security.log" if os.getenv("VERCEL") else "logs/security.log",
)


def setup_logger():
    log_directory = os.path.dirname(SECURITY_LOG_PATH)

    if log_directory:
        os.makedirs(log_directory, exist_ok=True)

    logging.basicConfig(
        filename=SECURITY_LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def format_log_value(value) -> str:
    text = str(value).replace("\n", " ").replace("\r", " ")

    if not text:
        return '""'

    if any(character.isspace() for character in text):
        escaped = text.replace('"', '\\"')
        return f'"{escaped}"'

    return text


def log_security_event(
    event: str,
    level: int = logging.INFO,
    **fields,
) -> None:
    field_text = " ".join(
        f"{key}={format_log_value(value)}"
        for key, value in fields.items()
        if value is not None
    )

    message = f"event={event}"

    if field_text:
        message = f"{message} {field_text}"

    logging.log(level, message)
    write_security_event_to_database(
        event=event,
        level=logging.getLevelName(level),
        message=message,
        field_text=field_text or None,
    )


def write_security_event_to_database(
    event: str,
    level: str,
    message: str,
    field_text: str | None,
) -> None:
    try:
        from app.database import SessionLocal

        db = SessionLocal()

        try:
            db.execute(
                text(
                    """
                    INSERT INTO security_logs
                        (event, level, message, fields, created_at)
                    VALUES
                        (:event, :level, :message, :fields, :created_at)
                    """
                ),
                {
                    "event": event,
                    "level": level,
                    "message": message,
                    "fields": field_text,
                    "created_at": datetime.now(timezone.utc),
                },
            )
            db.commit()
        finally:
            db.close()
    except (SQLAlchemyError, RuntimeError, ImportError):
        logging.debug(
            "Security log database write skipped.",
            exc_info=True,
        )


def log_replay_detection(
    replay_token: str,
    username: str | None = None,
    message_id: int | None = None,
) -> None:
    log_security_event(
        "REPLAY_DETECTED",
        level=logging.WARNING,
        username=username,
        message_id=message_id,
        replay_token=replay_token,
        action="rejected",
    )
