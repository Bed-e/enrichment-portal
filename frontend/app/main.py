"""Frontend entry point: uvicorn app.main:app --port 8001"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.backend_client import BackendClient
from app.config import Settings, get_settings
from app.routes import router

BASE_DIR = Path(__file__).parent


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    http = httpx.AsyncClient()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await http.aclose()

    app = FastAPI(title="Enrichment Portal", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.backend = BackendClient(http, settings.backend_url, settings.backend_timeout_seconds)
    app.state.templates = Jinja2Templates(directory=BASE_DIR / "templates")
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    app.include_router(router)
    return app


app = create_app()
