"""Engagement scope tracking and enforcement.

Every action endpoint must call `assert_in_scope` before touching hardware.
This module has no I/O dependencies so it can be fully unit tested without
a WiFi adapter attached.
"""

from threading import Lock


def _normalize_bssid(bssid: str) -> str:
    return bssid.strip().lower().replace("-", ":")


class ScopeNotSetError(Exception):
    pass


class OutOfScopeError(Exception):
    def __init__(self, target: str):
        self.target = target
        super().__init__(f"{target} is not in the authorized engagement scope")


class EngagementScope:
    """Holds the set of BSSIDs/SSIDs the operator has authorized for this engagement."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._bssids: set[str] = set()
        self._ssids: set[str] = set()
        self._is_set = False

    def set_scope(self, bssids: list[str] | None = None, ssids: list[str] | None = None) -> None:
        with self._lock:
            self._bssids = {_normalize_bssid(b) for b in (bssids or [])}
            self._ssids = {s.strip() for s in (ssids or [])}
            self._is_set = True

    def clear(self) -> None:
        with self._lock:
            self._bssids = set()
            self._ssids = set()
            self._is_set = False

    def is_set(self) -> bool:
        return self._is_set

    def as_dict(self) -> dict:
        return {"bssids": sorted(self._bssids), "ssids": sorted(self._ssids), "is_set": self._is_set}

    def is_authorized(self, *, bssid: str | None = None, ssid: str | None = None) -> bool:
        if not self._is_set:
            return False
        if bssid and _normalize_bssid(bssid) in self._bssids:
            return True
        if ssid and ssid in self._ssids:
            return True
        return False

    def assert_in_scope(self, *, bssid: str | None = None, ssid: str | None = None) -> None:
        if not self._is_set:
            raise ScopeNotSetError("Engagement scope has not been configured yet")
        if not self.is_authorized(bssid=bssid, ssid=ssid):
            raise OutOfScopeError(bssid or ssid or "<unknown target>")


# Process-wide singleton used by the API layer.
current_scope = EngagementScope()
