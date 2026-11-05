"""The frontend's only source of data: HTTP calls to the backend's JSON API."""

from urllib.parse import quote

import httpx
from pydantic import ValidationError

from app.models import LookupResult


class BackendBadRequest(Exception):
    """The backend rejected the input (HTTP 400). The message is safe to show."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class BackendUnavailable(Exception):
    """The backend could not be reached, timed out, or answered with something unusable."""


class BackendClient:
    def __init__(self, http: httpx.AsyncClient, base_url: str, timeout: float) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    async def lookup(self, ip: str) -> LookupResult:
        # Quote the user's text so it can only ever be one path segment.
        url = f"{self._base_url}/api/v1/ip/{quote(ip, safe='')}"
        try:
            response = await self._http.get(url, timeout=self._timeout)
        except httpx.HTTPError as exc:
            raise BackendUnavailable(type(exc).__name__) from None

        if response.status_code == 400:
            raise BackendBadRequest(self._message(response))
        if response.status_code != 200:
            raise BackendUnavailable(f"HTTP {response.status_code}")
        try:
            return LookupResult.model_validate(response.json())
        except (ValueError, ValidationError):
            raise BackendUnavailable("unexpected response shape") from None

    @staticmethod
    def _message(response: httpx.Response) -> str:
        try:
            message = response.json()["message"]
        except (ValueError, KeyError, TypeError):
            return "The backend rejected that input."
        return message if isinstance(message, str) and message else "Invalid input."
