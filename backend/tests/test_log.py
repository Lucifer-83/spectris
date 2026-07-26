from app import logging_db


def test_clear_log_wipes_and_leaves_marker(tmp_path):
    db = tmp_path / "log.sqlite3"
    logging_db.log_action("scan-start", "wlan1", "success", db_path=db)
    logging_db.log_action("wps-pixie", "AA:BB:CC:DD:EE:FF", "success", db_path=db)
    assert len(logging_db.get_log(db_path=db)) == 2

    removed = logging_db.clear_log(db_path=db)

    assert removed == 2
    rows = logging_db.get_log(db_path=db)
    # only the "log-cleared" marker survives, so the reset is itself audited
    assert len(rows) == 1
    assert rows[0]["action"] == "log-cleared"
    assert "2" in rows[0]["detail"]


def test_clear_empty_log_is_safe(tmp_path):
    db = tmp_path / "log.sqlite3"
    removed = logging_db.clear_log(db_path=db)
    assert removed == 0
    rows = logging_db.get_log(db_path=db)
    assert len(rows) == 1 and rows[0]["action"] == "log-cleared"
