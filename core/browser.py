"""
Optional headless-browser confirmation for XSS findings.

Uses Playwright (install via: pip install playwright && playwright install chromium)
to load an attack URL in a real browser and listen for ``alert()`` / ``confirm()``
execution.  Gracefully unavailable when Playwright is not installed.

Usage::

    confirmer = BrowserConfirmer()
    if await confirmer.is_available():
        confirmed = await confirmer.confirm_xss(attack_url)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Dialog, Page, TimeoutError as PWTimeoutError
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    PWTimeoutError = Exception  # fallback so except clauses compile


class BrowserConfirmer:
    """
    Confirm XSS and CSTI findings using a real headless Chromium browser.

    How it works:
    1. Opens a Playwright Chromium browser (headless).
    2. Navigates to the attack URL.
    3. Listens for ``dialog`` events (alert / confirm / prompt).
    4. Returns ``True`` if any dialog fires within the timeout window.

    The dialog is automatically dismissed so the browser doesn't hang.

    Instantiate once and reuse across multiple ``confirm_xss`` calls to
    avoid per-call browser startup overhead.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout * 1000  # Playwright uses milliseconds

    async def is_available(self) -> bool:
        """Return True if Playwright is installed and Chromium is reachable."""
        if not _PLAYWRIGHT_INSTALLED:
            logger.info(
                "Playwright not installed — browser confirmation disabled. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return False
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                await browser.close()
            return True
        except Exception as exc:
            logger.warning("Playwright available but Chromium launch failed: %s", exc)
            return False

    async def confirm_xss(self, attack_url: str) -> bool:
        """
        Load *attack_url* in a headless browser and return ``True`` if an
        ``alert()`` / ``confirm()`` / ``prompt()`` dialog fires.

        Args:
            attack_url: The full URL with injected XSS payload.

        Returns:
            ``True`` if JavaScript executed and triggered a dialog; ``False``
            otherwise (including timeouts, navigation errors, or no dialog).
        """
        if not _PLAYWRIGHT_INSTALLED:
            return False

        dialog_fired = False

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                page = await context.new_page()

                def _on_dialog(dialog: "Dialog") -> None:  # type: ignore[name-defined]
                    nonlocal dialog_fired
                    dialog_fired = True
                    asyncio.ensure_future(dialog.dismiss())

                page.on("dialog", _on_dialog)

                try:
                    await page.goto(attack_url, timeout=self._timeout, wait_until="domcontentloaded")
                    # Brief wait for deferred XSS (setTimeout, DOMContentLoaded handlers)
                    await page.wait_for_timeout(1500)
                except PWTimeoutError:
                    pass  # page may hang due to the payload — dialog may still have fired
                except Exception as exc:
                    logger.debug("Browser navigation error for %s: %s", attack_url, exc)

                await browser.close()

        except Exception as exc:
            logger.warning("Browser confirmation failed for %s: %s", attack_url, exc)
            return False

        if dialog_fired:
            logger.info("[BROWSER CONFIRMED] XSS dialog fired at: %s", attack_url)
        else:
            logger.debug("No dialog fired within timeout for: %s", attack_url)

        return dialog_fired

    async def confirm_csti(self, attack_url: str, expected_value: str = "49") -> bool:
        """
        Confirm CSTI by loading *attack_url* and checking page text for *expected_value*.

        Args:
            attack_url: URL with ``{{7*7}}`` or similar template expression injected.
            expected_value: The evaluated result to look for in the page body (default ``"49"``).

        Returns:
            ``True`` if the expected evaluated value is found in the rendered DOM.
        """
        if not _PLAYWRIGHT_INSTALLED:
            return False

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                try:
                    await page.goto(attack_url, timeout=self._timeout, wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)
                except PWTimeoutError:
                    pass
                except Exception as exc:
                    logger.debug("CSTI browser nav error: %s", exc)
                    await browser.close()
                    return False

                body_text = await page.inner_text("body")
                await browser.close()
                found = expected_value in body_text
                if found:
                    logger.info("[BROWSER CONFIRMED] CSTI value %r found at: %s", expected_value, attack_url)
                return found

        except Exception as exc:
            logger.warning("CSTI browser confirmation failed: %s", exc)
            return False
