"""CLI tests."""
from daccess.cli import main


def test_cli_demo_runs(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "rows_scanned" in out
    assert "chain valid: True" in out


def test_cli_compliance_runs(capsys):
    assert main(["compliance"]) == 0
    out = capsys.readouterr().out
    assert "total_grants" in out
    assert "expired_but_active" in out
