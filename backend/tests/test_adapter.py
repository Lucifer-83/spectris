import pytest

from app import adapter
from app.adapter import AdapterCommandError, WirelessInterface, interface_mode, set_monitor_mode


def _fake_interfaces(mode):
    return lambda: [WirelessInterface(name="wlan1", phy="phy4", mode=mode, supports_monitor=True)]


def test_enable_monitor_frees_from_nm_and_verifies(monkeypatch):
    calls, optional = [], []
    monkeypatch.setattr(adapter, "_run", lambda cmd: calls.append(cmd) or "")
    monkeypatch.setattr(adapter, "_run_optional", lambda cmd: optional.append(cmd))
    monkeypatch.setattr(adapter, "list_interfaces", _fake_interfaces("monitor"))

    result = set_monitor_mode("wlan1", True)

    assert result == "monitor"
    # NM is told to stop managing the interface (so it can't revert the switch)
    assert ["sudo", "-n", "nmcli", "dev", "set", "wlan1", "managed", "no"] in optional
    # and the mode is actually switched via iw
    assert ["sudo", "-n", "iw", "wlan1", "set", "type", "monitor"] in calls


def test_enable_monitor_raises_when_mode_did_not_stick(monkeypatch):
    monkeypatch.setattr(adapter, "_run", lambda cmd: "")
    monkeypatch.setattr(adapter, "_run_optional", lambda cmd: None)
    monkeypatch.setattr(adapter, "list_interfaces", _fake_interfaces("managed"))  # reverted

    with pytest.raises(AdapterCommandError):
        set_monitor_mode("wlan1", True)


def test_disable_monitor_hands_interface_back_to_nm(monkeypatch):
    optional = []
    monkeypatch.setattr(adapter, "_run", lambda cmd: "")
    monkeypatch.setattr(adapter, "_run_optional", lambda cmd: optional.append(cmd))
    monkeypatch.setattr(adapter, "list_interfaces", _fake_interfaces("managed"))

    result = set_monitor_mode("wlan1", False)

    assert result == "managed"
    assert ["sudo", "-n", "nmcli", "dev", "set", "wlan1", "managed", "yes"] in optional


def test_interface_mode_lookup(monkeypatch):
    monkeypatch.setattr(adapter, "list_interfaces", _fake_interfaces("monitor"))
    assert interface_mode("wlan1") == "monitor"
    assert interface_mode("wlan9") is None


# --- band detection -------------------------------------------------------

def test_bands_from_phy_info_dual_band():
    info = """
	Band 1:
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
			* 2437.0 MHz [6] (20.0 dBm)
	Band 2:
		Frequencies:
			* 5180.0 MHz [36] (20.0 dBm)
			* 5745.0 MHz [149] (20.0 dBm)
"""
    assert adapter._bands_from_phy_info(info) == ["2.4 GHz", "5 GHz"]


def test_bands_from_phy_info_24_only():
    info = "* 2412.0 MHz [1]\n* 2462.0 MHz [11]\n"
    assert adapter._bands_from_phy_info(info) == ["2.4 GHz"]


def test_bands_from_phy_info_includes_6ghz():
    info = "* 2412 MHz\n* 5180 MHz\n* 5955 MHz [1]\n"
    assert adapter._bands_from_phy_info(info) == ["2.4 GHz", "5 GHz", "6 GHz"]


def test_bands_empty_when_no_frequencies():
    assert adapter._bands_from_phy_info("no frequencies here") == []


# --- device identity (internal/external + model) --------------------------

def test_list_interfaces_enriches_with_device_info(monkeypatch):
    monkeypatch.setattr(adapter, "_run", lambda cmd: (
        "phy#11\n\tInterface wlan1\n\t\ttype monitor\n"
    ))
    monkeypatch.setattr(adapter, "phy_capabilities", lambda phy: (True, ["2.4 GHz"]))
    monkeypatch.setattr(
        adapter, "_device_info",
        lambda name: {"driver": "rt2800usb", "bus": "usb", "connection": "external",
                      "chipset": "Ralink 802.11 n WLAN (148f:5370)"},
    )

    ifaces = adapter.list_interfaces()

    assert len(ifaces) == 1
    dongle = ifaces[0]
    assert dongle.name == "wlan1"
    assert dongle.connection == "external"
    assert dongle.bus == "usb"
    assert dongle.driver == "rt2800usb"
    assert "148f:5370" in dongle.chipset
    assert dongle.bands == ["2.4 GHz"]


def test_device_info_missing_interface_is_safe(monkeypatch):
    # a non-existent interface must not raise — just return unknown/empty fields
    info = adapter._device_info("definitely-not-a-real-iface-xyz")
    assert info == {"driver": "", "bus": "unknown", "connection": "unknown", "chipset": ""}


# --- internal adapter: usable (with a warning), never destructively killed -----

def test_monitor_mode_allowed_on_internal_adapter(monkeypatch):
    # internal is NOT hard-blocked — with a single external card the operator
    # legitimately needs the built-in one as a second adapter (evil twin needs 2).
    calls = []
    monkeypatch.setattr(adapter, "is_internal", lambda iface: True)
    monkeypatch.setattr(adapter, "_run", lambda cmd: calls.append(cmd) or "")
    monkeypatch.setattr(adapter, "_run_optional", lambda cmd: None)
    monkeypatch.setattr(adapter, "list_interfaces", _fake_interfaces("monitor"))
    result = set_monitor_mode("wlan0", True)
    assert result == "monitor"
    assert ["sudo", "-n", "iw", "wlan0", "set", "type", "monitor"] in calls


def test_kill_interferers_is_surgical_not_global(monkeypatch):
    optional = []
    monkeypatch.setattr(adapter, "is_internal", lambda iface: False)
    monkeypatch.setattr(adapter, "_run_optional", lambda cmd: optional.append(cmd))
    adapter.kill_interfering_processes("wlan1")
    # frees only this interface via nmcli, and NEVER runs the global airmon-ng kill
    assert ["sudo", "-n", "nmcli", "dev", "set", "wlan1", "managed", "no"] in optional
    assert not any("airmon-ng" in " ".join(cmd) for cmd in optional)


def test_kill_interferers_works_on_internal_with_warning(monkeypatch):
    optional = []
    monkeypatch.setattr(adapter, "is_internal", lambda iface: True)
    monkeypatch.setattr(adapter, "_run_optional", lambda cmd: optional.append(cmd))
    out = adapter.kill_interfering_processes("wlan0")
    assert ["sudo", "-n", "nmcli", "dev", "set", "wlan0", "managed", "no"] in optional
    assert not any("airmon-ng" in " ".join(cmd) for cmd in optional)  # still never global
    assert "internal" in out.lower()  # but it warns it's the internet card
