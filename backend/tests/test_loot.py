from app import loot


def test_preserve_copies_existing_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRIS_LOOT_DIR", str(tmp_path / "loot"))
    f = tmp_path / "capture.pcapng"
    f.write_bytes(b"handshake-bytes")
    dest = loot.preserve([str(f)], "handshake")
    assert dest is not None
    assert (dest / "capture.pcapng").read_bytes() == b"handshake-bytes"
    assert str(dest).startswith(str(tmp_path / "loot"))
    assert "handshake_" in dest.name  # category + timestamp


def test_preserve_skips_empty_and_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRIS_LOOT_DIR", str(tmp_path / "loot"))
    empty = tmp_path / "empty.pcapng"
    empty.write_bytes(b"")
    # empty file, a non-existent path and a None are all skipped -> nothing to save
    assert loot.preserve([str(empty), str(tmp_path / "missing.pcapng"), None], "handshake") is None


def test_cleanup_removes_dir_and_is_safe_on_missing(tmp_path):
    d = tmp_path / "wifi_tmp"
    d.mkdir()
    (d / "junk.log").write_text("throwaway")
    loot.cleanup(d)
    assert not d.exists()
    # must never raise on None or a non-existent path
    loot.cleanup(None)
    loot.cleanup(tmp_path / "does-not-exist")
