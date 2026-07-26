from app.capture import channel_arg
from app.wpsscan import parse_wash_json


def test_channel_arg_adds_band_letter():
    assert channel_arg("6") == "6a"       # 2.4GHz
    assert channel_arg("11") == "11a"
    assert channel_arg("36") == "36b"     # 5GHz
    assert channel_arg("6a") == "6a"      # already banded -> unchanged
    assert channel_arg("auto") == "auto"  # non-numeric passes through


def test_parse_wash_json_array():
    raw = '[{"bssid":"AA:BB:CC:DD:EE:FF","wps_locked":0},{"bssid":"11:22:33:44:55:66","wps_locked":1}]'
    out = {a["bssid"]: a["locked"] for a in parse_wash_json(raw)}
    assert out["AA:BB:CC:DD:EE:FF"] is False
    assert out["11:22:33:44:55:66"] is True


def test_parse_wash_json_ndjson_and_case():
    raw = '{"bssid":"aa:bb:cc:dd:ee:ff","locked":"Yes"}\n{"BSSID":"11:22:33:44:55:66"}'
    out = {a["bssid"]: a["locked"] for a in parse_wash_json(raw)}
    assert out["AA:BB:CC:DD:EE:FF"] is True    # uppercased + locked parsed
    assert out["11:22:33:44:55:66"] is False   # missing lock -> not locked


def test_parse_wash_json_empty():
    assert parse_wash_json("") == []
    assert parse_wash_json("garbage not json") == []
