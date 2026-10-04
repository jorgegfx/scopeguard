from audit.log import AuditLogger, read_events


def test_read_events_roundtrips_and_filters(tmp_path):
    logger = AuditLogger(run_id="run-1", log_dir=tmp_path)
    logger.log_event("command_executed", {"command": ["nmap", "-sV"], "target": "10.0.0.1"})
    logger.log_event("result", {"command": ["nmap", "-sV"], "returncode": 0})

    all_events = read_events("run-1", tmp_path)
    assert len(all_events) == 2

    commands = read_events("run-1", tmp_path, event_type="command_executed")
    assert len(commands) == 1
    assert commands[0].payload["command"] == ["nmap", "-sV"]


def test_read_events_missing_log_returns_empty(tmp_path):
    assert read_events("no-such-run", tmp_path) == []


def test_read_events_skips_corrupt_lines(tmp_path):
    logger = AuditLogger(run_id="run-2", log_dir=tmp_path)
    logger.log_event("command_executed", {"command": ["curl"], "target": "10.0.0.1"})
    # Simulate a truncated/garbage line from a crashed run.
    with (tmp_path / "run-2.jsonl").open("a", encoding="utf-8") as f:
        f.write("{not valid json\n")

    events = read_events("run-2", tmp_path)
    assert len(events) == 1
    assert events[0].event_type == "command_executed"
