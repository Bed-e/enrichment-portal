"""JSON endpoints under /api/v1."""

from ipaddress import ip_address

from fastapi import APIRouter, Request

from app.core.models import LookupResponse
from app.errors import ApiError

router = APIRouter(prefix="/api/v1")


@router.get("/ip/{ip}", response_model=LookupResponse)
async def lookup_ip(ip: str, request: Request) -> LookupResponse:
    try:
        address = ip_address(ip.strip())
    except ValueError:
        raise ApiError(400, "invalid_ip", "That is not a valid IP address.") from None
    if address.version == 6:
        raise ApiError(
            400, "unsupported_ip_version", "IPv6 support is planned for a later version."
        )
    return await request.app.state.lookup_service.lookup(address)
