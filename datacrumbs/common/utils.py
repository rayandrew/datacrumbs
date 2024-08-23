import logging
from typing import Any, Tuple

from datacrumbs.common.status import ProfilerStatus


def convert_or_fail(type, value) -> Tuple[ProfilerStatus, Any]:
    try:
        return ProfilerStatus.SUCCESS, type(value)
    except Exception as e:
        logging.error(f"Type conversion for type {type} failed for value {value}")
        logging.error("  Exception: %s", e)
        return ProfilerStatus.CONVERT_ERROR, type()
