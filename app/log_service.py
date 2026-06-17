from dataclasses import dataclass
from pathlib import Path

from app.logger_config import SECURITY_LOG_PATH


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


def get_security_log_lines(limit: int = 250) -> list[SecurityLogLine]:
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
