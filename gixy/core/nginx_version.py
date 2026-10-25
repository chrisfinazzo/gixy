"""Parse explicitly supplied upstream nginx versions for audit checks."""


def parse_oss(version_str):
    """Parse an nginx Open Source X.Y.Z version into three integers.

    Args:
        version_str: Explicit version string, optionally prefixed with ``v``.

    Returns:
        Three-integer tuple, or ``None`` for absent or invalid input.
    """
    if not version_str or not isinstance(version_str, str):
        return None
    cleaned = version_str.strip()
    if cleaned.startswith("v"):
        cleaned = cleaned[1:]
    parts = cleaned.split(".")
    if len(parts) != 3 or not all(
        part and all("0" <= c <= "9" for c in part) for part in parts
    ):
        return None
    return tuple(int(part) for part in parts)
