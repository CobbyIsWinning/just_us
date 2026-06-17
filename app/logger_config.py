import logging
import os

SECURITY_LOG_PATH = "logs/security.log"


def setup_logger():
    os.makedirs("logs", exist_ok=True)

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
