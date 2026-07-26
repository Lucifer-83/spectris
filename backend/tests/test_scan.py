from fastapi.testclient import TestClient

from app.main import app
from app.scan import parse_airodump_csv


def test_scan_start_rejected_when_interface_not_in_monitor_mode(monkeypatch):
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "managed")
    resp = TestClient(app).post("/scan/start", json={"interface": "wlan1"})
    assert resp.status_code == 400
    assert "monitor" in resp.json()["detail"].lower()


def test_scan_start_allowed_when_in_monitor_mode(monkeypatch):
    monkeypatch.setattr("app.main.adapter.interface_mode", lambda iface: "monitor")
    started = {}
    monkeypatch.setattr("app.main.scan_manager.start", lambda iface: started.update(iface=iface))
    resp = TestClient(app).post("/scan/start", json={"interface": "wlan1"})
    assert resp.status_code == 200
    assert started["iface"] == "wlan1"

# Captured from a real airodump-ng run; note the leading blank line before
# the header, which previously broke parsing (rows[0] was an empty row).
SAMPLE_CSV = (
    "\r\n"
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
    "14:33:75:E4:98:68, 2026-07-20 01:34:53, 2026-07-20 01:35:14,  1, 130, WPA2 WPA, CCMP TKIP, PSK, -90,       15,        2,   0.  0.  0.  0,  11, Airtel_5980, \r\n"
    "DA:B0:20:C5:4B:C9, 2026-07-20 01:34:54, 2026-07-20 01:35:16,  4, 130, WPA2, CCMP, PSK, -89,       18,        0,   0.  0.  0.  0,   0, , \r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
    "AA:BB:CC:DD:EE:FF, 2026-07-20 01:35:00, 2026-07-20 01:35:10, -50,        3, (not associated) ,SomeSSID\r\n"
    "\r\n"
)


def test_parses_access_points_despite_leading_blank_line():
    aps = parse_airodump_csv(SAMPLE_CSV)
    assert len(aps) == 2
    assert aps[0].bssid == "14:33:75:E4:98:68"
    assert aps[0].ssid == "Airtel_5980"
    assert aps[0].channel == "1"
    assert aps[0].encryption == "WPA2 WPA"


def test_hidden_ssid_parses_as_empty_string():
    aps = parse_airodump_csv(SAMPLE_CSV)
    hidden = next(ap for ap in aps if ap.bssid == "DA:B0:20:C5:4B:C9")
    assert hidden.ssid == ""


def test_station_section_is_excluded():
    aps = parse_airodump_csv(SAMPLE_CSV)
    bssids = {ap.bssid for ap in aps}
    assert "AA:BB:CC:DD:EE:FF" not in bssids


def test_empty_input_returns_empty_list():
    assert parse_airodump_csv("") == []


CSV_WITH_CLIENTS = (
    "\r\n"
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
    "14:33:75:E4:98:68, t, t,  1, 130, WPA2, CCMP, PSK, -50, 15, 2, 0.0.0.0, 11, Airtel_5980, \r\n"
    "DA:B0:20:C5:4B:C9, t, t,  4, 130, WPA2, CCMP, PSK, -89, 18, 0, 0.0.0.0, 0, Empty, \r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
    "11:11:11:11:11:11, t, t, -40, 3, 14:33:75:E4:98:68, \r\n"
    "22:22:22:22:22:22, t, t, -42, 5, 14:33:75:E4:98:68, \r\n"
    "33:33:33:33:33:33, t, t, -60, 1, (not associated) , foo\r\n"
    "\r\n"
)


def test_counts_connected_clients_per_ap():
    aps = {ap.bssid: ap for ap in parse_airodump_csv(CSV_WITH_CLIENTS)}
    assert aps["14:33:75:E4:98:68"].clients == 2  # two associated stations
    assert aps["DA:B0:20:C5:4B:C9"].clients == 0  # none; the 3rd client is unassociated
