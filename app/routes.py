import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import authenticate_user, create_user
from app.attack_service import (
    simulate_bruteforce_attack,
    simulate_mitm_tampering,
    simulate_replay_attack,
)
from app.database import get_db
from app.log_service import get_security_log_lines
from app.logger_config import log_security_event
from app.message_service import (
    create_general_message,
    create_private_message,
    get_visible_messages,
)
from app.models import User
from app.room_service import (
    create_room,
    ensure_default_room_for_user,
    get_active_room_for_user,
    get_joinable_rooms,
    get_room_by_slug,
    get_user_rooms,
    join_room,
    leave_room,
    user_is_room_member,
)
from app.storage_service import get_stored_keys, get_stored_messages

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


def parse_message_content(
    content: str,
) -> tuple[str, str | None, str]:
    cleaned_content = content.strip()

    if not cleaned_content:
        raise ValueError("Message cannot be empty.")

    if not cleaned_content.startswith("@"):
        return "general", None, cleaned_content

    parts = cleaned_content.split(maxsplit=1)

    if len(parts) != 2:
        raise ValueError(
            "Private messages must use: @username message"
        )

    username_part, message_body = parts

    recipient_username = (
        username_part
        .removeprefix("@")
        .strip()
        .lower()
    )

    message_body = message_body.strip()

    if not recipient_username:
        raise ValueError(
            "Private message recipient is missing."
        )

    if not message_body:
        raise ValueError(
            "Private message content is missing."
        )

    return (
        "private",
        recipient_username,
        message_body,
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
    confirm_password: str = Form(...),
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

    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Passwords do not match.",
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
        log_security_event(
            "REGISTRATION_DUPLICATE_REJECTED",
            level=logging.WARNING,
            username=username,
            action="rejected",
        )

        logging.debug(
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

    log_security_event(
        "USER_REGISTERED",
        username=username,
        user_id=user.id,
    )

    logging.debug(
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
        logging.debug(
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

    log_security_event(
        "SESSION_CREATED",
        username=username,
        user_id=user.id,
    )

    logging.debug(
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
        log_security_event(
            "LOGOUT",
            username=username,
        )

        logging.debug(
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
    room: str | None = None,
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

    active_room = get_active_room_for_user(
        db=db,
        user=current_user,
        room_slug=room,
    )

    user_rooms = get_user_rooms(
        db=db,
        user=current_user,
    )

    joinable_rooms = get_joinable_rooms(
        db=db,
        user=current_user,
    )

    messages = get_visible_messages(
        db=db,
        current_user=current_user,
        room=active_room,
    )
    general_messages = [
        message
        for message in messages
        if message.message_type == "general"
    ]
    private_messages = [
        message
        for message in messages
        if message.message_type == "private"
    ]
    security_summary = {
        "total_messages": len(messages),
        "verified_messages": sum(
            1
            for message in messages
            if message.integrity_verified
        ),
        "failed_messages": sum(
            1
            for message in messages
            if not message.integrity_verified
        ),
        "private_messages": len(private_messages),
    }

    return templates.TemplateResponse(
        request=request,
        name="room.html",
        context={
            "username": current_user.username,
            "users": users,
            "active_room": active_room,
            "user_rooms": user_rooms,
            "joinable_rooms": joinable_rooms,
            "messages": messages,
            "general_messages": general_messages,
            "private_messages": private_messages,
            "security_summary": security_summary,
            "error": error,
            "success": success,
        },
    )


@router.post("/room/messages", response_class=HTMLResponse)
def send_message(
    request: Request,
    content: str = Form(...),
    room_slug: str = Form(...),
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

    active_room = get_room_by_slug(
        db=db,
        slug=room_slug,
    )

    if not active_room or not user_is_room_member(
        db=db,
        room=active_room,
        user=current_user,
    ):
        log_security_event(
            "ROOM_ACCESS_DENIED",
            username=current_user.username,
            user_id=current_user.id,
            room_slug=room_slug,
            action="message_blocked",
        )

        return RedirectResponse(
            url="/room?error=You%20must%20join%20that%20room%20before%20sending.",
            status_code=303,
        )

    room_query = quote(active_room.slug)

    try:
        (
            message_type,
            recipient_username,
            message_body,
        ) = parse_message_content(content)
    except ValueError as error:
        return RedirectResponse(
            url=f"/room?room={room_query}&error={quote(str(error))}",
            status_code=303,
        )

    try:
        if message_type == "general":
            create_general_message(
                db=db,
                sender=current_user,
                room=active_room,
                plaintext=message_body,
            )

            success_message = (
                f"General message encrypted and sent to "
                f"#{active_room.slug}."
            )
        else:
            recipient = (
                db.query(User)
                .filter(
                    User.username == recipient_username,
                    User.is_active.is_(True),
                )
                .first()
            )

            if not recipient:
                return RedirectResponse(
                    url=(
                        f"/room?room={room_query}&error="
                        + quote(
                            f"User @{recipient_username} does not exist."
                        )
                    ),
                    status_code=303,
                )

            create_private_message(
                db=db,
                sender=current_user,
                recipient=recipient,
                plaintext=message_body,
            )

            success_message = (
                f"Private message encrypted and sent "
                f"to @{recipient.username}."
            )

    except ValueError as error:
        return RedirectResponse(
            url=f"/room?room={room_query}&error={quote(str(error))}",
            status_code=303,
        )

    except Exception:
        logging.exception(
            "Message creation failed. Sender=%s",
            current_user.username,
        )

        return RedirectResponse(
            url=(
                f"/room?room={room_query}"
                "&error=Message%20could%20not%20be%20sent."
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=f"/room?room={room_query}&success=" + quote(success_message),
        status_code=303,
    )


@router.post("/rooms", response_class=HTMLResponse)
def create_room_route(
    request: Request,
    name: str = Form(...),
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

    try:
        room = create_room(
            db=db,
            name=name,
            creator=current_user,
        )
    except ValueError as error:
        return RedirectResponse(
            url=f"/room?error={quote(str(error))}",
            status_code=303,
        )

    return RedirectResponse(
        url=(
            f"/room?room={quote(room.slug)}&success="
            + quote(f"Room #{room.slug} created.")
        ),
        status_code=303,
    )


@router.post("/rooms/join", response_class=HTMLResponse)
def join_room_route(
    request: Request,
    room_slug: str = Form(...),
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

    room = get_room_by_slug(
        db=db,
        slug=room_slug,
    )

    if not room:
        return RedirectResponse(
            url="/room?error=Room%20does%20not%20exist.",
            status_code=303,
        )

    join_room(
        db=db,
        room=room,
        user=current_user,
    )

    return RedirectResponse(
        url=(
            f"/room?room={quote(room.slug)}&success="
            + quote(f"Joined #{room.slug}.")
        ),
        status_code=303,
    )


@router.post("/rooms/leave", response_class=HTMLResponse)
def leave_room_route(
    request: Request,
    room_slug: str = Form(...),
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

    room = get_room_by_slug(
        db=db,
        slug=room_slug,
    )

    if not room:
        return RedirectResponse(
            url="/room?error=Room%20does%20not%20exist.",
            status_code=303,
        )

    try:
        leave_room(
            db=db,
            room=room,
            user=current_user,
        )
    except ValueError as error:
        return RedirectResponse(
            url=f"/room?room={quote(room.slug)}&error={quote(str(error))}",
            status_code=303,
        )

    fallback_room = ensure_default_room_for_user(
        db=db,
        user=current_user,
    )

    return RedirectResponse(
        url=(
            f"/room?room={quote(fallback_room.slug)}&success="
            + quote(f"Left #{room.slug}. Future messages use a rotated key.")
        ),
        status_code=303,
    )


@router.get(
    "/dev/storage",
    response_class=HTMLResponse,
)
def developer_storage_page(
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

    messages = get_stored_messages(db)
    keys = get_stored_keys(db)

    log_security_event(
        "STORAGE_VIEW_ACCESSED",
        username=current_user.username,
        user_id=current_user.id,
        message_records=len(messages),
        key_records=len(keys),
    )

    logging.debug(
        "Developer encrypted-storage view accessed by %s",
        current_user.username,
    )

    return templates.TemplateResponse(
        request=request,
        name="storage.html",
        context={
            "username": current_user.username,
            "messages": messages,
            "keys": keys,
        },
    )


@router.get("/logs", response_class=HTMLResponse)
def logs_page(
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

    log_lines = get_security_log_lines()

    log_security_event(
        "LOG_VIEW_ACCESSED",
        username=current_user.username,
        user_id=current_user.id,
        displayed_lines=len(log_lines),
    )

    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={
            "username": current_user.username,
            "log_lines": log_lines,
        },
    )


def render_attacks_page(
    request: Request,
    current_user: User,
    result=None,
):
    return templates.TemplateResponse(
        request=request,
        name="attacks.html",
        context={
            "username": current_user.username,
            "result": result,
        },
    )


@router.get("/attacks", response_class=HTMLResponse)
def attacks_page(
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

    log_security_event(
        "ATTACK_VIEW_ACCESSED",
        username=current_user.username,
        user_id=current_user.id,
    )

    return render_attacks_page(
        request=request,
        current_user=current_user,
    )


@router.post("/attacks/mitm", response_class=HTMLResponse)
def run_mitm_attack(
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

    result = simulate_mitm_tampering(
        db=db,
        current_user=current_user,
    )

    return render_attacks_page(
        request=request,
        current_user=current_user,
        result=result,
    )


@router.post("/attacks/replay", response_class=HTMLResponse)
def run_replay_attack(
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

    result = simulate_replay_attack(
        db=db,
        current_user=current_user,
    )

    return render_attacks_page(
        request=request,
        current_user=current_user,
        result=result,
    )


@router.post("/attacks/bruteforce", response_class=HTMLResponse)
def run_bruteforce_attack(
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

    result = simulate_bruteforce_attack(db)

    return render_attacks_page(
        request=request,
        current_user=current_user,
        result=result,
    )
