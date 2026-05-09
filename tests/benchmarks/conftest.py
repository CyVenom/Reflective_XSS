"""Benchmark-specific pytest configuration.

Provides the ``bench_loop`` fixture: a module-scoped asyncio event loop reused
across all sync benchmark functions.  Using loop.run_until_complete() instead of
asyncio.run() prevents asyncio.run() from setting the current loop to None, which
would otherwise break any subsequent tests that still use asyncio.get_event_loop().
"""
from __future__ import annotations

import asyncio

import pytest


@pytest.fixture(scope="module")
def bench_loop():
    """
    A persistent event loop for benchmark tests.

    Benchmark functions are sync (pytest-benchmark only supports sync callables),
    so they call loop.run_until_complete() on this shared loop instead of
    asyncio.run().  The loop stays open for the whole module, preventing the
    event-loop-becomes-None side-effect that asyncio.run() would cause.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()
    # Restore a fresh default loop so tests outside this module that still use
    # asyncio.get_event_loop() (e.g. test_crawler.py) continue to work.
    asyncio.set_event_loop(asyncio.new_event_loop())
