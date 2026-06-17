import re
from datetime import timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.crypto_utils import generate_message_keys, protect_message_keys
from app.logger_config import log_security_event
from app.models import ConversationKey, Message, Room, RoomMembership, User, utc_now


DEFAULT_ROOM_NAME = "General"
DEFAULT_ROOM_SLUG = "general"
ROOM_KEY_SCOPE = "room"


def slugify_room_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    slug = slug.strip("-")

    if not slug:
        raise ValueError("Room name must contain letters or numbers.")

    return slug[:80]


def get_default_room(db: Session) -> Room:
    room = (
        db.query(Room)
        .filter(Room.slug == DEFAULT_ROOM_SLUG)
        .first()
    )

    if room:
        return room

    room = Room(
        name=DEFAULT_ROOM_NAME,
        slug=DEFAULT_ROOM_SLUG,
        is_default=True,
    )

    db.add(room)
    db.commit()
    db.refresh(room)

    log_security_event(
        "ROOM_CREATED",
        room_id=room.id,
        room_slug=room.slug,
        default=True,
    )

    return room


def backfill_default_room_records(
    db: Session,
    room: Room,
) -> None:
    updated_messages = (
        db.query(Message)
        .filter(
            Message.message_type == "general",
            Message.room_id.is_(None),
        )
        .update(
            {Message.room_id: room.id},
            synchronize_session=False,
        )
    )

    updated_keys = (
        db.query(ConversationKey)
        .filter(
            ConversationKey.key_scope == ROOM_KEY_SCOPE,
            ConversationKey.room_id.is_(None),
            ConversationKey.user_a_id.is_(None),
            ConversationKey.user_b_id.is_(None),
        )
        .update(
            {ConversationKey.room_id: room.id},
            synchronize_session=False,
        )
    )

    if updated_messages or updated_keys:
        db.commit()


def get_membership(
    db: Session,
    room: Room,
    user: User,
) -> RoomMembership | None:
    return (
        db.query(RoomMembership)
        .filter(
            RoomMembership.room_id == room.id,
            RoomMembership.user_id == user.id,
        )
        .first()
    )


def join_room(
    db: Session,
    room: Room,
    user: User,
) -> RoomMembership:
    membership = get_membership(
        db=db,
        room=room,
        user=user,
    )

    if membership:
        if not membership.is_active:
            membership.is_active = True
            membership.joined_at = utc_now()
            membership.left_at = None
            db.commit()

            log_security_event(
                "ROOM_JOINED",
                username=user.username,
                user_id=user.id,
                room_id=room.id,
                room_slug=room.slug,
            )

        return membership

    membership = RoomMembership(
        room_id=room.id,
        user_id=user.id,
        is_active=True,
    )

    db.add(membership)
    db.commit()
    db.refresh(membership)

    log_security_event(
        "ROOM_JOINED",
        username=user.username,
        user_id=user.id,
        room_id=room.id,
        room_slug=room.slug,
    )

    return membership


def ensure_default_room_for_user(
    db: Session,
    user: User,
) -> Room:
    room = get_default_room(db)
    backfill_default_room_records(db, room)
    join_room(db, room, user)
    return room


def user_is_room_member(
    db: Session,
    room: Room,
    user: User,
) -> bool:
    membership = get_membership(
        db=db,
        room=room,
        user=user,
    )

    return bool(membership and membership.is_active)


def get_user_rooms(
    db: Session,
    user: User,
) -> list[Room]:
    return (
        db.query(Room)
        .join(RoomMembership)
        .filter(
            RoomMembership.user_id == user.id,
            RoomMembership.is_active.is_(True),
        )
        .order_by(Room.is_default.desc(), Room.name.asc())
        .all()
    )


def get_joinable_rooms(
    db: Session,
    user: User,
) -> list[Room]:
    active_room_ids = [
        membership.room_id
        for membership in (
            db.query(RoomMembership)
            .filter(
                RoomMembership.user_id == user.id,
                RoomMembership.is_active.is_(True),
            )
            .all()
        )
    ]

    query = db.query(Room).order_by(Room.name.asc())

    if active_room_ids:
        query = query.filter(Room.id.notin_(active_room_ids))

    return query.all()


def get_room_by_slug(
    db: Session,
    slug: str,
) -> Room | None:
    return (
        db.query(Room)
        .filter(Room.slug == slug)
        .first()
    )


def get_active_room_for_user(
    db: Session,
    user: User,
    room_slug: str | None,
) -> Room:
    ensure_default_room_for_user(db, user)

    if room_slug:
        room = get_room_by_slug(db, room_slug)

        if room and user_is_room_member(db, room, user):
            return room

        log_security_event(
            "ROOM_ACCESS_DENIED",
            username=user.username,
            user_id=user.id,
            room_slug=room_slug,
        )

    user_rooms = get_user_rooms(db, user)
    return user_rooms[0]


def create_room(
    db: Session,
    name: str,
    creator: User,
) -> Room:
    cleaned_name = name.strip()

    if len(cleaned_name) < 3:
        raise ValueError("Room name must contain at least 3 characters.")

    slug = slugify_room_name(cleaned_name)
    existing_room = get_room_by_slug(db, slug)

    if existing_room:
        raise ValueError("A room with that name already exists.")

    room = Room(
        name=cleaned_name[:80],
        slug=slug,
        created_by_id=creator.id,
        is_default=False,
    )

    db.add(room)
    db.commit()
    db.refresh(room)

    log_security_event(
        "ROOM_CREATED",
        username=creator.username,
        user_id=creator.id,
        room_id=room.id,
        room_slug=room.slug,
    )

    join_room(db, room, creator)

    return room


def get_latest_room_key_version(
    db: Session,
    room: Room,
) -> int:
    latest_version = (
        db.query(func.max(ConversationKey.key_version))
        .filter(
            ConversationKey.key_scope == ROOM_KEY_SCOPE,
            ConversationKey.room_id == room.id,
        )
        .scalar()
    )

    return latest_version or 0


def rotate_room_key(
    db: Session,
    room: Room,
    actor: User,
) -> ConversationKey:
    key_version = get_latest_room_key_version(db, room) + 1
    protected_keys = protect_message_keys(generate_message_keys())

    key_record = ConversationKey(
        key_scope=ROOM_KEY_SCOPE,
        room_id=room.id,
        user_a_id=None,
        user_b_id=None,
        key_version=key_version,
        key_value=protected_keys,
    )

    db.add(key_record)
    db.commit()
    db.refresh(key_record)

    log_security_event(
        "ROOM_KEY_ROTATED",
        username=actor.username,
        user_id=actor.id,
        room_id=room.id,
        room_slug=room.slug,
        key_version=key_version,
    )

    return key_record


def leave_room(
    db: Session,
    room: Room,
    user: User,
) -> None:
    if room.is_default:
        raise ValueError("The default room cannot be left.")

    membership = get_membership(
        db=db,
        room=room,
        user=user,
    )

    if not membership or not membership.is_active:
        raise ValueError("You are not a member of that room.")

    membership.is_active = False
    membership.left_at = utc_now().astimezone(timezone.utc)
    db.commit()

    log_security_event(
        "ROOM_LEFT",
        username=user.username,
        user_id=user.id,
        room_id=room.id,
        room_slug=room.slug,
    )

    rotate_room_key(db, room, user)
