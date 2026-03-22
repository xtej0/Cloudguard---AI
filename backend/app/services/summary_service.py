from __future__ import annotations

from datetime import datetime, timezone


def build_attack_summary_message(
    start: str | None,
    target: str | None,
    path_exists: bool,
    start_exists: bool | None = None,
    target_exists: bool | None = None,
) -> str:
    """Build user-facing attack summary message for invalid input, no-path, or success states."""
    if start_exists is False and target_exists is False:
        return "Invalid input: start and target assets not found"
    if start_exists is False:
        return f"Invalid input: start asset '{start}' not found"
    if target_exists is False:
        return f"Invalid input: target asset '{target}' not found"
    if not path_exists:
        return f"No attack path found between '{start}' and '{target}'"
    return "Attack path successfully found"


def utc_now_iso() -> str:
    """Return current UTC timestamp as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()