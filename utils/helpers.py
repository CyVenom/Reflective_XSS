"""General-purpose utility helpers shared across the framework."""

from __future__ import annotations

import random
import string
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse


def generate_marker(length: int = 8) -> str:
    """
    Generate a random alphabetic marker for reflection detection.

    Using letters only avoids false positives from numeric strings that may
    naturally appear in web responses.

    Args:
        length: Number of characters (default 8 is sufficient to avoid collisions).

    Returns:
        A random uppercase/lowercase alphabetic string.
    """
    return "".join(random.choices(string.ascii_letters, k=length))


def inject_marker_into_payload(payload: str, marker: str) -> str:
    """
    Embed *marker* into *payload* by replacing the first occurrence of a
    known placeholder value.

    The scanner later checks if *marker* appears in the response, which
    confirms reflection without relying on payload-specific strings.

    Args:
        payload: Raw XSS payload template.
        marker: Unique detection string to embed.

    Returns:
        Payload with the marker substituted in.
    """
    for placeholder in ("1", "document.cookie", "XSS", "x"):
        if placeholder in payload:
            return payload.replace(placeholder, marker, 1)
    # Fallback: append the marker after the payload
    return payload + marker


def build_url_with_param(
    base_url: str,
    params: dict[str, str],
    target_param: str,
    value: str,
) -> str:
    """
    Reconstruct *base_url* with *target_param* replaced by *value*.

    All other query parameters are preserved as-is.

    Args:
        base_url: The original URL.
        params: Flat mapping of all current query parameters.
        target_param: The parameter key to replace.
        value: The new value for *target_param*.

    Returns:
        The fully-formed attack URL as a string.
    """
    modified = {**params, target_param: value}
    parsed: ParseResult = urlparse(base_url)
    return parsed._replace(query=urlencode(modified)).geturl()


def extract_params(url: str) -> dict[str, str]:
    """
    Parse and return a flat dict of query parameters from *url*.

    Multi-value parameters are flattened to their first value, matching
    common server-side behaviour.

    Args:
        url: URL string with optional query string.

    Returns:
        ``{param_name: first_value}`` mapping, empty dict if no query string.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in qs.items()}


def normalize_url(url: str) -> str:
    """
    Ensure *url* has an HTTP/HTTPS scheme, defaulting to HTTPS.

    Args:
        url: Raw URL string that may be missing a scheme.

    Returns:
        URL guaranteed to start with ``https://`` or ``http://``.
    """
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url
