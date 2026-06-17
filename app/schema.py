from sqlalchemy import inspect, text

from app.database import engine


def ensure_schema_updates():
    inspector = inspect(engine)

    existing_tables = set(inspector.get_table_names())

    with engine.begin() as connection:
        if "messages" in existing_tables:
            message_columns = {
                column["name"]
                for column in inspector.get_columns("messages")
            }

            if "room_id" not in message_columns:
                connection.execute(
                    text(
                        "ALTER TABLE messages "
                        "ADD COLUMN room_id INTEGER REFERENCES rooms(id)"
                    )
                )

            if "key_version" not in message_columns:
                connection.execute(
                    text(
                        "ALTER TABLE messages "
                        "ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1"
                    )
                )

        if "conversation_keys" in existing_tables:
            key_columns = {
                column["name"]
                for column in inspector.get_columns("conversation_keys")
            }

            if "room_id" not in key_columns:
                connection.execute(
                    text(
                        "ALTER TABLE conversation_keys "
                        "ADD COLUMN room_id INTEGER REFERENCES rooms(id)"
                    )
                )

            if "key_version" not in key_columns:
                connection.execute(
                    text(
                        "ALTER TABLE conversation_keys "
                        "ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1"
                    )
                )
