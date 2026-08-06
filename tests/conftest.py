"""Shared test isolation.

``app.observability.logging.configure_logging`` is global and irreversible by
design. It does three things that outlive the test that triggered them:

1. ``logging.basicConfig(..., force=True)`` removes every root handler,
   including pytest's capture handler;
2. ``structlog.configure(wrapper_class=make_filtering_bound_logger(level))``
   installs a wrapper that drops records below ``INFO`` *before* they reach the
   standard library, so ``caplog.set_level(DEBUG)`` cannot get them back;
3. ``cache_logger_on_first_use=True`` means every module-level
   ``logger = get_logger(__name__)`` caches that filtering wrapper on its first
   call — and restoring the configuration afterwards does **not** clear it.

All three are right for a process that starts once and runs until it stops.
None are right for a test session that starts the application dozens of times.

The concrete symptom was
``tests/unit/test_vault.py::test_no_plaintext_mapping_appears_in_logs_when_encryption_fails``
passing when its file ran alone and failing when the whole tree ran in one
session: by then another file had started an app, and the vault's cached logger
was silently discarding the DEBUG records the test asserts on. An order-
dependent failure in a privacy assertion is the worst combination — it reads as
flake, and the thing it guards is a plaintext leak.

Point 3 is why this fixture reaches into ``BoundLoggerLazyProxy``. structlog
offers no public way to un-cache a logger, and without it the other two
restorations achieve nothing.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

import pytest
import structlog

if TYPE_CHECKING:
    from collections.abc import Iterator

_LAZY_PROXY_TYPE = type(structlog.get_logger("tests.conftest.probe"))
"""``structlog.BoundLoggerLazyProxy``, obtained without importing a private name."""

_CACHED_BIND = "bind"
"""What ``cache_logger_on_first_use`` writes onto a proxy.

Only this one. ``_logger`` is set in ``__init__`` and is *not* the cache;
deleting it makes ``__getattr__`` call ``bind()``, which reads ``self._logger``,
which calls ``__getattr__`` again — a ``RecursionError`` on the first log call
of the next test. Removing the cached ``bind`` is sufficient: the next attribute
access falls through to the class method and rebinds under the current
configuration.
"""


def _clear_cached_loggers() -> None:
    """Make every module-level logger rebind on its next use.

    Module loggers are created once at import and cached on first call, so a
    logger warmed while the application's configuration was installed keeps that
    configuration for the rest of the session.
    """
    for name, module in list(sys.modules.items()):
        if not name.startswith(("app.", "scripts.")):
            continue
        for value in list(vars(module).values()):
            if isinstance(value, _LAZY_PROXY_TYPE):
                value.__dict__.pop(_CACHED_BIND, None)


@pytest.fixture(autouse=True)
def _isolate_logging_configuration() -> Iterator[None]:
    root = logging.getLogger()
    saved_structlog: dict[str, Any] = structlog.get_config()
    saved_handlers = list(root.handlers)
    saved_level = root.level

    try:
        yield
    finally:
        structlog.configure(**saved_structlog)
        _clear_cached_loggers()
        root.setLevel(saved_level)
        # Put back anything configure_logging removed, without disturbing
        # handlers pytest attached in the meantime -- it manages its own capture
        # handler per phase and does not need help.
        for handler in saved_handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
