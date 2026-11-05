"""Backend entry point: uvicorn app.main:app"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from app.api.routes import router
from app.config import Settings, get_settings
from app.errors import register_error_handlers
from app.services.lookup import LookupService
from app.sources.base import SourceClient
from app.sources.registry import build_sources


def create_app(
    settings: Settings | None = None, sources: list[SourceClient] | None = None
) -> FastAPI:
    settings = settings or get_settings()
    http = httpx.AsyncClient(follow_redirects=True)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await http.aclose()

    app = FastAPI(title="Enrichment Portal API", lifespan=lifespan)
    app.state.lookup_service = LookupService(
        sources if sources is not None else build_sources(settings, http)
    )
    register_error_handlers(app)
    app.include_router(router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
