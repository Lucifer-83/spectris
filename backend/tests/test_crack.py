import pytest
from fastapi.testclient import TestClient

from app import crack
from app.crack import CrackCommandError, CrackManager, _build_command, _parse_progress, hashcat_benchmark, list_wordlists
from app.main import app
from app.scope import current_scope


@pytest.fixture(autouse=True)
def reset_scope():
    current_scope.clear()
    yield
    current_scope.clear()


@pytest.fixture
def client():
    return TestClient(app)


# --- scope gating (the safety guardrail) ---------------------------------

def test_crack_start_rejected_when_scope_never_set(client):
    resp = client.post(
        "/crack/start",
        json={"bssid": "AA:BB:CC:DD:EE:FF", "wordlist": "/usr/share/wordlists/rockyou.txt"},
    )
    assert resp.status_code == 400


def test_crack_start_rejected_for_out_of_scope_bssid(client):
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/crack/start",
        json={"bssid": "11:22:33:44:55:66", "wordlist": "/usr/share/wordlists/rockyou.txt"},
    )
    assert resp.status_code == 403


def test_crack_start_never_invokes_manager_when_out_of_scope(client, monkeypatch):
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("crack_manager.start must not run for an out-of-scope target")

    monkeypatch.setattr("app.main.crack_manager.start", fail_if_called)
    current_scope.set_scope(bssids=["AA:BB:CC:DD:EE:FF"])
    resp = client.post(
        "/crack/start",
        json={"bssid": "11:22:33:44:55:66", "wordlist": "/usr/share/wordlists/rockyou.txt"},
    )
    assert resp.status_code == 403
    assert called is False


# --- command construction -------------------------------------------------

def test_hashcat_command_uses_mode_22000(tmp_path):
    cmd, outfile = _build_command(
        "hashcat", "/caps/x.hc22000", "/wl/rockyou.txt", None, "AA:BB:CC:DD:EE:FF", tmp_path
    )
    assert cmd[0] == "hashcat"
    assert "22000" in cmd and "/caps/x.hc22000" in cmd and "/wl/rockyou.txt" in cmd
    assert outfile is not None and outfile.name == "cracked.txt"
    # offline crack must never be invoked with sudo
    assert "sudo" not in cmd


def test_aircrack_command_reads_pcapng_and_bssid(tmp_path):
    cmd, outfile = _build_command(
        "aircrack", "/caps/x.hc22000", "/wl/rockyou.txt", "/caps/x.pcapng", "AA:BB:CC:DD:EE:FF", tmp_path
    )
    assert cmd[0] == "aircrack-ng"
    assert "-b" in cmd and "AA:BB:CC:DD:EE:FF" in cmd and "/caps/x.pcapng" in cmd
    assert outfile is None
    assert "sudo" not in cmd


def test_aircrack_without_pcapng_raises(tmp_path):
    with pytest.raises(CrackCommandError):
        _build_command("aircrack", "/caps/x.hc22000", "/wl/rockyou.txt", None, "AA:BB:CC:DD:EE:FF", tmp_path)


def test_unknown_engine_raises(tmp_path):
    with pytest.raises(CrackCommandError):
        _build_command("john", "/caps/x.hc22000", "/wl/rockyou.txt", None, "AA:BB:CC:DD:EE:FF", tmp_path)


def test_hashcat_rules_mode_adds_rule_flag(tmp_path):
    rules = tmp_path / "best64.rule"
    rules.write_text(":\n")
    cmd, _ = _build_command(
        "hashcat", "/caps/x.hc22000", "/wl/rockyou.txt", None, "AA:BB:CC:DD:EE:FF", tmp_path,
        attack_mode="rules", rules=str(rules),
    )
    assert "-r" in cmd and str(rules) in cmd and "-a" in cmd and "0" in cmd


def test_hashcat_mask_mode_uses_bruteforce(tmp_path):
    cmd, _ = _build_command(
        "hashcat", "/caps/x.hc22000", "", None, "AA:BB:CC:DD:EE:FF", tmp_path,
        attack_mode="mask", mask="?d?d?d?d?d?d?d?d",
    )
    assert "-a" in cmd and "3" in cmd and "?d?d?d?d?d?d?d?d" in cmd


def test_mask_mode_rejects_empty_or_spaced_mask(tmp_path):
    with pytest.raises(CrackCommandError):
        _build_command("hashcat", "/caps/x.hc22000", "", None, "AA:BB:CC:DD:EE:FF", tmp_path,
                       attack_mode="mask", mask="")
    with pytest.raises(CrackCommandError):
        _build_command("hashcat", "/caps/x.hc22000", "", None, "AA:BB:CC:DD:EE:FF", tmp_path,
                       attack_mode="mask", mask="?d ?d")


def test_mask_mode_rejects_leading_dash(tmp_path):
    # a mask starting with '-' would be read by hashcat as an option through the
    # trailing mask positional (argument injection) — must be rejected.
    with pytest.raises(CrackCommandError):
        _build_command("hashcat", "/caps/x.hc22000", "", None, "AA:BB:CC:DD:EE:FF", tmp_path,
                       attack_mode="mask", mask="--outfile=/tmp/x")


def test_mask_mode_allows_literal_prefix_mask(tmp_path):
    # a legit mask mixing literal chars with charset tokens must still work.
    cmd, _ = _build_command("hashcat", "/caps/x.hc22000", "", None, "AA:BB:CC:DD:EE:FF", tmp_path,
                            attack_mode="mask", mask="Summer?d?d?d?d")
    assert "Summer?d?d?d?d" in cmd


def test_rules_mode_requires_existing_file(tmp_path):
    with pytest.raises(CrackCommandError):
        _build_command("hashcat", "/caps/x.hc22000", "/wl/rockyou.txt", None, "AA:BB:CC:DD:EE:FF", tmp_path,
                       attack_mode="rules", rules="/does/not/exist.rule")


def test_aircrack_rejects_non_wordlist_modes(tmp_path):
    with pytest.raises(CrackCommandError):
        _build_command("aircrack", "/caps/x.hc22000", "/wl/rockyou.txt", "/caps/x.pcapng",
                       "AA:BB:CC:DD:EE:FF", tmp_path, attack_mode="mask", mask="?d?d")


def test_parse_progress_hashcat_takes_last_block():
    raw = (
        "Progress.........: 100/14344385 (0.00%)\n"
        "Speed.#1.........: 500 H/s\n"
        "Progress.........: 7200000/14344385 (50.19%)\n"
        "Speed.#1.........: 12345 H/s\n"
        "Time.Estimated...: Thu (1 hour, 2 mins)\n"
    )
    pct, speed, eta = _parse_progress("hashcat", raw)
    assert pct == 50.19
    assert speed == "12345 H/s"
    assert eta == "1 hour, 2 mins"


def test_parse_progress_aircrack_computes_percent():
    raw = "[00:00:12] 7172192/14344385 keys tested (1000.00 k/s)\n"
    pct, speed, eta = _parse_progress("aircrack", raw)
    assert pct == 50.0
    assert "kH/s" in (speed or "")


# --- output parsing -------------------------------------------------------

def test_status_reads_hashcat_recovered_key_from_outfile(tmp_path):
    mgr = CrackManager()
    mgr._engine = "hashcat"
    mgr._outfile = tmp_path / "cracked.txt"
    mgr._outfile.write_text("SuperSecret123\n")
    mgr._log_file = tmp_path / "crack.log"
    mgr._log_file.write_text("Status...........: Cracked\n")
    state = mgr.status()
    assert state.psk == "SuperSecret123"
    assert state.running is False


def test_status_parses_aircrack_key_found(tmp_path):
    mgr = CrackManager()
    mgr._engine = "aircrack"
    mgr._log_file = tmp_path / "crack.log"
    mgr._log_file.write_text("Reading packets...\nKEY FOUND! [ hunter2secret ]\n")
    state = mgr.status()
    assert state.psk == "hunter2secret"


def test_status_flags_exhausted_wordlist(tmp_path):
    mgr = CrackManager()
    mgr._engine = "hashcat"
    mgr._outfile = tmp_path / "cracked.txt"  # never created -> no key
    mgr._log_file = tmp_path / "crack.log"
    mgr._log_file.write_text("Status...........: Exhausted\n")

    # simulate a finished process so status() knows the run is over
    class _Done:
        def poll(self):
            return 0
    mgr._process = _Done()

    state = mgr.status()
    assert state.psk is None
    assert state.exhausted is True


def test_status_does_not_flag_exhausted_on_tool_error(tmp_path):
    # a run that FAILED with a generic "not found" error (e.g. no OpenCL device)
    # must NOT be reported as "wordlist exhausted" — that would tell the operator the
    # password is definitively absent when the run actually errored out.
    mgr = CrackManager()
    mgr._engine = "hashcat"
    mgr._outfile = tmp_path / "cracked.txt"  # never created -> no key
    mgr._log_file = tmp_path / "crack.log"
    mgr._log_file.write_text("clGetDeviceIDs(): CL_DEVICE_NOT_FOUND\nNo devices found/left.\n")

    class _Done:
        def poll(self):
            return 1  # non-zero: the run errored, did not exhaust the keyspace
    mgr._process = _Done()

    state = mgr.status()
    assert state.psk is None
    assert state.exhausted is False  # was True before the fix (it matched "not found")


# --- hashcat benchmark (Setup page speed check) ---------------------------

def test_hashcat_benchmark_parses_speed_lines(monkeypatch):
    monkeypatch.setattr(crack.shutil, "which", lambda name: "/usr/bin/hashcat")

    class _Proc:
        stdout = (
            "hashcat (v6.2) starting in benchmark mode\n"
            "Hashmode: 22000 - WPA-PBKDF2-PMKID+EAPOL\n"
            "Speed.#1.........:    12345 H/s (55.00ms)\n"
            "Speed.#*.........:    12345 H/s\n"
        )
        stderr = ""

    monkeypatch.setattr(crack.subprocess, "run", lambda *a, **k: _Proc())
    result = hashcat_benchmark()
    assert "22000" in result["mode"]
    assert result["speeds"] and any("H/s" in s for s in result["speeds"])


def test_hashcat_benchmark_missing_tool_raises(monkeypatch):
    monkeypatch.setattr(crack.shutil, "which", lambda name: None)
    with pytest.raises(CrackCommandError):
        hashcat_benchmark()


# --- bundled default wordlist (ships with the app) -----------------------

def test_list_wordlists_includes_bundled_default_first():
    lists = list_wordlists()
    assert lists, "expected at least the bundled wordlist"
    first = lists[0]
    assert first.get("bundled") is True
    assert first["path"].endswith(".txt")
    assert first["needs_gunzip"] is False
    # the bundled file must actually exist and be non-empty
    from pathlib import Path
    assert Path(first["path"]).is_file() and first["size"] > 0
