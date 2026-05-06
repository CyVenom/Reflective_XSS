"""Async HTTP client with retry logic, configurable timeouts, and session management."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout

from core.config import ScannerConfig

logger = logging.getLogger(__name__)


@dataclass
class HTTPResponse:
    """Normalised representation of an HTTP response."""

    status: int
    text: str
    headers: dict[str, str]
    url: str


class HTTPClient:
    """
    Async HTTP client with automatic retry and exponential back-off.

    Intended to be used as an async context manager so the underlying
    ``aiohttp.ClientSession`` is properly closed after use:

    .. code-block:: python

        async with HTTPClient(config) as client:
            response = await client.get("https://example.com/?q=test")

    The client can also be instantiated without the context manager when the
    caller manages session lifetime manually via :meth:`close`.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config
        self._session: Optional[ClientSession] = None

    # ------------------------------------------------------------------
    # Context-manager protocol
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "HTTPClient":
        await self._create_session()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> Optional[HTTPResponse]:
        """Send a GET request, returning ``None`` on permanent failure."""
        return await self._request("GET", url, **kwargs)

    async def post(
        self, url: str, data: dict[str, str], **kwargs: Any
    ) -> Optional[HTTPResponse]:
        """Send a POST request with form-encoded *data*."""
        return await self._request("POST", url, data=data, **kwargs)

    async def close(self) -> None:
        """Close the underlying session if it is open."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _create_session(self) -> None:
        connector = aiohttp.TCPConnector(ssl=self._config.verify_ssl)
        timeout = ClientTimeout(total=self._config.timeout)
        headers = {"User-Agent": self._config.user_agent}
        self._session = ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
        )

    async def _request(
        self, method: str, url: str, **kwargs: Any
    ) -> Optional[HTTPResponse]:
        """
        Execute *method* against *url* with exponential back-off retry.

        Args:
            method: HTTP verb (``GET``, ``POST``, …).
            url: Fully-qualified target URL.
            **kwargs: Extra arguments forwarded to ``aiohttp.ClientSession.request``.

        Returns:
            An :class:`HTTPResponse` on success, ``None`` after all retries are
            exhausted.
        """
        if self._session is None:
            await self._create_session()

        for attempt in range(self._config.max_retries + 1):
            try:
                assert self._session is not None
                async with self._session.request(
                    method,
                    url,
                    allow_redirects=self._config.follow_redirects,
                    **kwargs,
                ) as resp:
                    text = await resp.text(errors="replace")
                    return HTTPResponse(
                        status=resp.status,
                        text=text,
                        headers=dict(resp.headers),
                        url=str(resp.url),
                    )

            except asyncio.TimeoutError:
                logger.debug(
                    "Timeout on %s %s (attempt %d/%d)",
                    method, url, attempt + 1, self._config.max_retries + 1,
                )
            except aiohttp.ClientError as exc:
                logger.debug(
                    "Client error on %s %s: %s (attempt %d/%d)",
                    method, url, exc, attempt + 1, self._config.max_retries + 1,
                )

            if attempt < self._config.max_retries:
                delay = self._config.retry_delay * (2 ** attempt)
                await asyncio.sleep(delay)

        logger.warning("All retries exhausted for %s %s", method, url)
        return None
