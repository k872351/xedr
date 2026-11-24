"""Validate browser write origins against the public request authority."""
from urllib.parse import urlsplit


def same_write_origin(origin: str, host: str, scheme: str) -> bool:
    if not origin:
        return True
    if scheme not in ("http", "https"):
        return False
    try:
        given = urlsplit(origin)
        target = urlsplit(f"{scheme}://{host}")
        for item in (given, target):
            if not item.hostname or item.username is not None or item.password is not None:
                return False
            if item.path or item.query or item.fragment:
                return False
            if item.scheme not in ("http", "https"):
                return False
        given_port = given.port if given.port is not None else (443 if given.scheme == "https" else 80)
        target_port = target.port if target.port is not None else (443 if target.scheme == "https" else 80)
        return (given.scheme, given.hostname, given_port) == (target.scheme, target.hostname, target_port)
    except (ValueError, TypeError):
        return False
