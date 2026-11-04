"""Shared pytest fixtures.

Event loop guard: several tests build Telethon / Pyrogram-family clients
synchronously, and those constructors call ``asyncio.get_event_loop()``.
After an earlier test has used ``asyncio.run()`` (which leaves the current
loop unset), that call raises "There is no current event loop" on Python
3.9-3.11, so the outcome would depend on test order. Before each test,
make sure a usable current loop exists. Close the loop afterwards only if
this fixture created it.
"""

from __future__ import annotations

import asyncio
import warnings

import pytest


@pytest.fixture(autouse=True)
def _usable_current_event_loop():
    created = None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            usable = not asyncio.get_event_loop_policy().get_event_loop().is_closed()
        except RuntimeError:
            usable = False
        if not usable:
            created = asyncio.new_event_loop()
            asyncio.set_event_loop(created)
    yield
    if created is not None and not created.is_closed():
        created.close()
