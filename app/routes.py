import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import authenticate_user, create_user
from app.database import get_db
from app.message_service import create_general_message, get_general_messages
from app.models import User

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


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
    error: str | None = None,
    success: str | None = None,
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

    messages = get_general_messages(db)

    return templates.TemplateResponse(
        request=request,
        name="room.html",
        context={
            "username": current_user.username,
            "users": users,
            "messages": messages,
            "error": error,
            "success": success,
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

    cleaned_content = content.strip()

    if not cleaned_content:
        return RedirectResponse(
            url="/room?error=Message+cannot+be+empty",
            status_code=303,
        )

    if cleaned_content.startswith("@"):
        return RedirectResponse(
            url="/room?error=Private+messaging+will+be+added+in+Milestone+6",
            status_code=303,
        )

    try:
        create_general_message(
            db=db,
            sender=current_user,
            plaintext=cleaned_content,
        )
    except Exception:
        logging.exception(
            "General message creation failed for user: %s",
            current_user.username,
        )

        return RedirectResponse(
            url="/room?error=Message+could+not+be+sent",
            status_code=303,
        )

    return RedirectResponse(
        url="/room?success=Message+encrypted+and+sent",
        status_code=303,
    )
