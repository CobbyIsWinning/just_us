import logging
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import authenticate_user, create_user
from app.database import get_db
from app.models import User

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


@dataclass
class DemoMessage:
    sender: str
    content: str
    message_type: str
    recipient: str | None = None


demo_messages: list[DemoMessage] = []


def parse_message_content(
    content: str,
) -> tuple[str, str | None, str]:
    cleaned_content = content.strip()

    if not cleaned_content:
        raise ValueError("Message cannot be empty.")

    if not cleaned_content.startswith("@"):
        return "general", None, cleaned_content

    parts = cleaned_content.split(maxsplit=1)

    if len(parts) < 2:
        raise ValueError(
            "Private messages must include a username and message."
        )

    username_part = parts[0]
    message_body = parts[1].strip()
    recipient_username = username_part[1:].strip().lower()

    if not recipient_username:
        raise ValueError("Private message recipient is missing.")

    if not message_body:
        raise ValueError("Private message content is missing.")

    return "private", recipient_username, message_body


def get_visible_demo_messages(username: str) -> list[DemoMessage]:
    visible_messages = []

    for message in demo_messages:
        if message.message_type == "general":
            visible_messages.append(message)
            continue

        if message.sender == username or message.recipient == username:
            visible_messages.append(message)

    return visible_messages


def get_current_user(
    request: Request,
    db: Session,
) -> User | None:
    user_id = request.session.get("user_id")

    if not user_id:
        return None

    return (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(
            url="/room",
            status_code=302,
        )

    return RedirectResponse(
        url="/login",
        status_code=302,
    )


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(
            url="/room",
            status_code=302,
        )

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "error": None,
            "success": None,
        },
    )


@router.post("/register", response_class=HTMLResponse)
def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip().lower()

    if len(username) < 3:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Username must contain at least 3 characters.",
                "success": None,
            },
            status_code=400,
        )

    if not username.replace("_", "").isalnum():
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": (
                    "Username may contain only letters, "
                    "numbers, and underscores."
                ),
                "success": None,
            },
            status_code=400,
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Password must contain at least 8 characters.",
                "success": None,
            },
            status_code=400,
        )

    user = create_user(
        db=db,
        username=username,
        password=password,
    )

    if not user:
        logging.warning(
            "Registration rejected for duplicate username: %s",
            username,
        )

        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Username already exists.",
                "success": None,
            },
            status_code=409,
        )

    logging.info(
        "New user registered: %s",
        username,
    )

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "error": None,
            "success": "Registration successful. You can now log in.",
        },
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(
            url="/room",
            status_code=302,
        )

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None,
        },
    )


@router.post("/login", response_class=HTMLResponse)
def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip().lower()

    user, error = authenticate_user(
        db=db,
        username=username,
        password=password,
    )

    if error:
        logging.warning(
            "Login failed for %s: %s",
            username,
            error,
        )

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": error,
            },
            status_code=401,
        )

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["username"] = user.username

    logging.info(
        "User logged in: %s",
        username,
    )

    return RedirectResponse(
        url="/room",
        status_code=303,
    )


@router.get("/logout")
def logout_user(request: Request):
    username = request.session.get("username")

    request.session.clear()

    if username:
        logging.info(
            "User logged out: %s",
            username,
        )

    return RedirectResponse(
        url="/login",
        status_code=302,
    )


@router.get("/room", response_class=HTMLResponse)
def room_page(
    request: Request,
    db: Session = Depends(get_db),
):
    current_user = get_current_user(
        request=request,
        db=db,
    )

    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=302,
        )

    users = (
        db.query(User)
        .filter(User.is_active.is_(True))
        .order_by(User.username.asc())
        .all()
    )

    return templates.TemplateResponse(
        request=request,
        name="room.html",
        context={
            "username": current_user.username,
            "users": users,
            "messages": get_visible_demo_messages(current_user.username),
            "error": None,
            "success": None,
        },
    )


@router.post("/room/messages", response_class=HTMLResponse)
def send_message(
    request: Request,
    content: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(
        request=request,
        db=db,
    )

    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=302,
        )

    users = (
        db.query(User)
        .filter(User.is_active.is_(True))
        .order_by(User.username.asc())
        .all()
    )

    visible_messages = get_visible_demo_messages(current_user.username)

    try:
        message_type, recipient_username, message_body = parse_message_content(
            content
        )
    except ValueError as error:
        return templates.TemplateResponse(
            request=request,
            name="room.html",
            context={
                "username": current_user.username,
                "users": users,
                "messages": visible_messages,
                "error": str(error),
                "success": None,
            },
            status_code=400,
        )

    if message_type == "private":
        recipient = (
            db.query(User)
            .filter(
                User.username == recipient_username,
                User.is_active.is_(True),
            )
            .first()
        )

        if not recipient:
            return templates.TemplateResponse(
                request=request,
                name="room.html",
                context={
                    "username": current_user.username,
                    "users": users,
                    "messages": visible_messages,
                    "error": f"User @{recipient_username} does not exist.",
                    "success": None,
                },
                status_code=404,
            )

        if recipient.id == current_user.id:
            return templates.TemplateResponse(
                request=request,
                name="room.html",
                context={
                    "username": current_user.username,
                    "users": users,
                    "messages": visible_messages,
                    "error": "You cannot send a private message to yourself.",
                    "success": None,
                },
                status_code=400,
            )

    demo_messages.append(
        DemoMessage(
            sender=current_user.username,
            content=message_body,
            message_type=message_type,
            recipient=recipient_username,
        )
    )

    if message_type == "general":
        logging.info(
            "General demo message sent by %s",
            current_user.username,
        )
    else:
        logging.info(
            "Private demo message sent by %s to %s",
            current_user.username,
            recipient_username,
        )

    return RedirectResponse(
        url="/room",
        status_code=303,
    )
