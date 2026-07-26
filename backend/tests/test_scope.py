import pytest

from app.scope import EngagementScope, OutOfScopeError, ScopeNotSetError


def test_assert_in_scope_fails_when_scope_never_set():
    scope = EngagementScope()
    with pytest.raises(ScopeNotSetError):
        scope.assert_in_scope(bssid="AA:BB:CC:DD:EE:FF")


def test_authorized_bssid_passes():
    scope = EngagementScope()
    scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    scope.assert_in_scope(bssid="AA:BB:CC:DD:EE:FF")  # should not raise


def test_bssid_matching_is_case_and_separator_insensitive():
    scope = EngagementScope()
    scope.set_scope(bssids=["aa:bb:cc:dd:ee:ff"])
    scope.assert_in_scope(bssid="AA-BB-CC-DD-EE-FF")  # should not raise


def test_unauthorized_bssid_is_rejected():
    scope = EngagementScope()
    scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    with pytest.raises(OutOfScopeError):
        scope.assert_in_scope(bssid="11:22:33:44:55:66")


def test_authorized_ssid_passes():
    scope = EngagementScope()
    scope.set_scope(ssids=["CorpGuest"])
    scope.assert_in_scope(ssid="CorpGuest")  # should not raise


def test_unauthorized_ssid_is_rejected():
    scope = EngagementScope()
    scope.set_scope(ssids=["CorpGuest"])
    with pytest.raises(OutOfScopeError):
        scope.assert_in_scope(ssid="NeighborWifi")


def test_clear_resets_scope_to_unset():
    scope = EngagementScope()
    scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    scope.clear()
    with pytest.raises(ScopeNotSetError):
        scope.assert_in_scope(bssid="AA:BB:CC:DD:EE:FF")


def test_is_authorized_returns_bool_without_raising():
    scope = EngagementScope()
    scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    assert scope.is_authorized(bssid="AA:BB:CC:DD:EE:FF") is True
    assert scope.is_authorized(bssid="11:22:33:44:55:66") is False
