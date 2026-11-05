"""Frontend routes: server-rendered HTML pages."""

from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from app.backend_client import BackendBadRequest, BackendUnavailable

router = APIRouter()

UNAVAILABLE_MESSAGE = (
    "Backend unavailable. The lookup service could not be reached, so nothing was looked up. "
    "Check that the backend is running and try again."
)


def _page(request: Request, **context: object) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(request, "index.html", context)


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return _page(request, ip_input="", result=None, error=None)


@router.post("/lookup", response_class=HTMLResponse)
async def lookup(request: Request, ip: Annotated[str, Form()] = "") -> HTMLResponse:
    ip = ip.strip()
    if not ip:
        return _page(request, ip_input="", result=None, error="Enter an IP address.")
    try:
        result = await request.app.state.backend.lookup(ip)
    except BackendBadRequest as exc:
        return _page(request, ip_input=ip, result=None, error=exc.message)
    except BackendUnavailable:
        return _page(request, ip_input=ip, result=None, error=UNAVAILABLE_MESSAGE)
    return _page(request, ip_input=ip, result=result, error=None)


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
