import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, engine
from app.logger_config import setup_logger
from app.routes import router
from app.schema import ensure_schema_updates

load_dotenv()
setup_logger()

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing from .env")

app = FastAPI(
    title="Just Us",
    description="Secure room messaging system",
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=False,
)

Base.metadata.create_all(bind=engine)
ensure_schema_updates()

app.include_router(router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": "Just Us",
    }
