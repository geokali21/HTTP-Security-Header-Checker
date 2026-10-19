import json

from header_checker.cli import EXIT_INVALID, EXIT_NETWORK, EXIT_OK, main
from header_checker.fetcher import fetch
from header_checker.models import FetchResult
from header_checker.report import build_report, render_terminal, to_html, to_json


def test_secure_profile_report_over_http(secure_server):
    rep = build_report(fetch(secure_server))
    st = {f.name: f.status.value for f in rep.findings}
    assert st["Strict-Transport-Security"] == "REVIEW"   # HTTP, cannot evaluate
    assert st["Content-Security-Policy"] == "FOUND"
    assert rep.summary["FOUND"] == 5


def test_mixed_profile_statuses(mixed_server):
    st = {f.name: f.status.value for f in build_report(fetch(mixed_server)).findings}
    assert st["Content-Security-Policy"] == "REVIEW"
    assert st["Referrer-Policy"] == "REVIEW"
    assert st["Permissions-Policy"] == "MISSING"


def test_outputs_never_contain_decoy_secrets(mixed_server):
    rep = build_report(fetch(mixed_server))
    blob = to_json(rep) + to_html(rep) + render_terminal(rep)
    assert "SECRET_TEST_VALUE" not in blob and "DemoServer" not in blob


def test_json_is_valid_and_has_expected_keys(weak_server):
    data = json.loads(to_json(build_report(fetch(weak_server))))
    assert {"target", "final_url", "findings", "summary", "disclaimer"} <= data.keys()
    assert data["findings"][0]["status"] in ("FOUND", "MISSING", "REVIEW")


def test_html_escapes_untrusted_header_values():
    res = FetchResult("http://x/", "http://x/", 200, ["http://x/"],
                      {"Referrer-Policy": "<script>alert(1)</script>"}, 1)
    out = to_html(build_report(res))
    assert "<script>alert(1)</script>" not in out and "&lt;script&gt;" in out


def test_cli_demo_writes_reports(tmp_path, capsys):
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    assert main(["--demo", "mixed", "--json", str(j), "--html", str(h)]) == EXIT_OK
    assert "[MISSING]" in capsys.readouterr().out
    assert json.loads(j.read_text())["summary"]["REVIEW"] >= 2
    assert h.read_text().startswith("<!DOCTYPE html>")


def test_cli_invalid_url(capsys):
    assert main(["notaurl"]) == EXIT_INVALID


def test_cli_requires_authorization_for_remote_targets(capsys):
    assert main(["https://example.com"]) == EXIT_INVALID
    assert "--confirm-authorized" in capsys.readouterr().err


def test_cli_network_error_exit_code(capsys):
    assert main(["http://127.0.0.1:1/", "--timeout", "2"]) == EXIT_NETWORK
