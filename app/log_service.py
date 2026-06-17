from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from app.database import SessionLocal
from app.logger_config import SECURITY_LOG_PATH
from app.models import SecurityLog


@dataclass
class SecurityLogLine:
    number: int
    content: str
    level: str


def classify_log_level(content: str) -> str:
    if " - ERROR - " in content:
        return "error"

    if " - WARNING - " in content:
        return "warning"

    return "info"


def classify_database_level(level: str) -> str:
    normalized_level = level.lower()

    if normalized_level == "error":
        return "error"

    if normalized_level == "warning":
        return "warning"

    return "info"


def get_database_security_log_lines(
    limit: int,
) -> list[SecurityLogLine]:
    db = SessionLocal()

    try:
        records = (
            db.query(SecurityLog)
            .order_by(SecurityLog.created_at.desc(), SecurityLog.id.desc())
            .limit(limit)
            .all()
        )
    finally:
        db.close()

    records.reverse()

    return [
        SecurityLogLine(
            number=record.id,
            content=(
                f"{record.created_at} - {record.level} - "
                f"{record.message}"
            ),
            level=classify_database_level(record.level),
        )
        for record in records
    ]


def get_security_log_lines(limit: int = 250) -> list[SecurityLogLine]:
    try:
        database_lines = get_database_security_log_lines(limit)

        if database_lines:
            return database_lines
    except (SQLAlchemyError, RuntimeError):
        pass

    log_path = Path(SECURITY_LOG_PATH)

    if not log_path.exists():
        return []

    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start_line_number = max(len(lines) - limit, 0) + 1

    return [
        SecurityLogLine(
            number=line_number,
            content=content,
            level=classify_log_level(content),
        )
        for line_number, content in enumerate(
            lines[-limit:],
            start=start_line_number,
        )
    ]
