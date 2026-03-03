# =============================================================================
# BinModder - Logging Utilities
# =============================================================================
# Thin wrapper around the standard library logging module that gives every
# BinModder component a consistent, coloured log format with optional
# file-sink support.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import logging
import sys
from pathlib import Path
from typing import Optional


# =============================================================================
# ANSI colour helpers (no extra deps)
# =============================================================================

_RESET  = "\033[0m"
_COLORS = {
    logging.DEBUG:    "\033[36m",   # cyan
    logging.INFO:     "\033[32m",   # green
    logging.WARNING:  "\033[33m",   # yellow
    logging.ERROR:    "\033[31m",   # red
    logging.CRITICAL: "\033[35m",   # magenta
}


class _ColourFormatter(logging.Formatter):
    """Formatter that prepends ANSI colour codes to the level name."""

    FMT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    DATE = "%H:%M:%S"

    def __init__(self, use_colour: bool = True) -> None:
        super().__init__(fmt=self.FMT, datefmt=self.DATE)
        self._use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:
        if self._use_colour:
            colour = _COLORS.get(record.levelno, "")
            record.levelname = f"{colour}{record.levelname}{_RESET}"
        return super().format(record)


# =============================================================================
# BinModderLogger
# =============================================================================

class BinModderLogger:
    """Factory and manager for BinModder loggers.

    Usage
    -----
    >>> log = BinModderLogger.get("core.patch_engine")
    >>> log.info("Patch applied at 0x%08X", offset)

    All loggers created through this class share the same root handler
    configuration set by :meth:`configure`.
    """

    _root_name = "binmodder"
    _configured = False

    # ------------------------------------------------------------------
    # Configuration (call once at startup)
    # ------------------------------------------------------------------

    @classmethod
    def configure(
        cls,
        level: int = logging.INFO,
        log_file: Optional["str | Path"] = None,
        use_colour: bool = True,
    ) -> None:
        """Set up the root BinModder logger.

        Parameters
        ----------
        level : int
            Minimum log level (``logging.DEBUG``, ``logging.INFO``, …).
        log_file : str | Path | None
            If given, log records are also written to this file (no colour).
        use_colour : bool
            Whether to emit ANSI colour codes on the stream handler.
        """
        root = logging.getLogger(cls._root_name)
        root.setLevel(level)
        root.handlers.clear()

        # Console handler
        stream_h = logging.StreamHandler(sys.stdout)
        stream_h.setFormatter(_ColourFormatter(use_colour=use_colour))
        root.addHandler(stream_h)

        # Optional file handler
        if log_file:
            file_h = logging.FileHandler(log_file, encoding="utf-8")
            file_h.setFormatter(_ColourFormatter(use_colour=False))
            root.addHandler(file_h)

        root.propagate = False
        cls._configured = True

    # ------------------------------------------------------------------
    # Logger factory
    # ------------------------------------------------------------------

    @classmethod
    def get(cls, name: str = "") -> logging.Logger:
        """Return a child logger under the ``binmodder`` namespace.

        Parameters
        ----------
        name : str
            Sub-logger name, e.g. ``"core.hex_engine"``.  An empty string
            returns the root ``binmodder`` logger.
        """
        if not cls._configured:
            cls.configure()
        full = f"{cls._root_name}.{name}" if name else cls._root_name
        return logging.getLogger(full)

    # ------------------------------------------------------------------
    # Convenience wrappers (instance usage)
    # ------------------------------------------------------------------

    def __init__(self, name: str = "") -> None:
        self._logger = self.get(name)

    def debug(self, msg: str, *args, **kwargs) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self._logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs) -> None:
        self._logger.critical(msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs) -> None:
        self._logger.exception(msg, *args, **kwargs)
