"""Report building and rendering (terminal, JSON, HTML)."""
from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List

from . import __version__
from .models import FetchResult, HeaderFinding, Report, Status
from .rules import evaluate

DISCLAIMER = (
    "Findings are observations and potential risks based on one HTTP GET response. "
    "A missing or weak header does not by itself confirm a vulnerability, and this "
    "report is not a security score or a complete assessment."
)
COLORS = {Status.FOUND: "\033[32m", Status.MISSING: "\033[31m", Status.REVIEW: "\033[33m"}
RESET = "\033[0m"


def build_report(result: FetchResult) -> Report:
    findings = evaluate(result.headers, result.final_url)
    summary = {s.value: sum(1 for f in findings if f.status == s) for s in Status}
    return Report("HTTP Security Header Checker", __version__,
                  datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  result.requested_url, result.final_url, result.status_code,
                  result.redirect_chain, result.elapsed_ms, findings, summary,
                  list(result.notes), DISCLAIMER)


def to_dict(report: Report) -> dict:
    return json.loads(json.dumps(asdict(report), default=lambda o: o.value))


def to_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False)


def render_terminal(report: Report, color: bool = False, verbose: bool = False) -> str:
    def tag(s: Status) -> str:
        text = f"[{s.value}]"
        return f"{COLORS[s]}{text}{RESET}" if color else text

    L: List[str] = [
        "=" * 64,
        f" {report.tool} v{report.version}",
        "=" * 64,
        f"Target      : {report.target}",
        f"Final URL   : {report.final_url}",
        f"HTTP status : {report.status_code}   ({report.elapsed_ms} ms)",
    ]
    if len(report.redirect_chain) > 1:
        L.append("Redirects   : " + " -> ".join(report.redirect_chain))
    L.append("-" * 64)
    for f in report.findings:
        L.append(f"{tag(f.status)} {f.name}")
        if f.observed_value is not None:
            L.append(f"    Value      : {f.observed_value}")
        L.append(f"    Observation: {f.reason}")
        if f.status != Status.FOUND or verbose:
            L.append(f"    Purpose    : {f.purpose}")
            L.append(f"    Potential risk: {f.risk}")
            L.append(f"    Mitigation : {f.mitigation}")
        L.append("")
    s = report.summary
    L.append(f"Summary: {s['FOUND']} found, {s['MISSING']} missing, {s['REVIEW']} to review")
    for n in report.notes:
        L.append(f"Note: {n}")
    L.append(f"Disclaimer: {report.disclaimer}")
    return "\n".join(L)


def to_html(report: Report) -> str:
    e = html.escape
    badge = {"FOUND": "#1a7f37", "MISSING": "#cf222e", "REVIEW": "#9a6700"}
    cards = []
    for f in report.findings:
        val = f"<p><b>Value:</b> <code>{e(f.observed_value)}</code></p>" if f.observed_value else ""
        cards.append(
            f'<section><h2>{e(f.name)} <span class="b" style="background:{badge[f.status.value]}">'
            f"{f.status.value}</span></h2>{val}"
            f"<p><b>Observation:</b> {e(f.reason)}</p>"
            f"<p><b>Purpose:</b> {e(f.purpose)}</p>"
            f"<p><b>Potential risk:</b> {e(f.risk)}</p>"
            f"<p><b>Mitigation:</b> {e(f.mitigation)}</p>"
            f"<p><b>Re-verify:</b> {e(f.verification)}</p>"
            f"<p><b>Limitation:</b> {e(f.limitation)}</p></section>")
    s = report.summary
    notes = "".join(f"<li>{e(n)}</li>" for n in report.notes)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{e(report.tool)} report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1f2328}}
section{{border:1px solid #d0d7de;border-radius:8px;padding:.5rem 1rem;margin:1rem 0}}
.b{{color:#fff;font-size:.7em;padding:2px 8px;border-radius:10px;vertical-align:middle}}
code{{background:#f6f8fa;padding:2px 4px;word-break:break-all}}
.disc{{background:#fff8c5;padding:.7rem 1rem;border-radius:8px}}
</style></head><body>
<h1>{e(report.tool)}</h1>
<p><b>Target:</b> {e(report.target)}<br><b>Final URL:</b> {e(report.final_url)}<br>
<b>HTTP status:</b> {report.status_code} &middot; <b>Generated:</b> {e(report.generated_at)}</p>
<p><b>Summary:</b> {s['FOUND']} found, {s['MISSING']} missing, {s['REVIEW']} to review</p>
{"<ul>" + notes + "</ul>" if notes else ""}
{''.join(cards)}
<p class="disc">{e(report.disclaimer)}</p>
</body></html>
"""
