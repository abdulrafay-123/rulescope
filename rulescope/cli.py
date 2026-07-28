"""Typer CLI for RuleScope."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import uvicorn

from rulescope.diff import diff_rulesets
from rulescope.eve import correlate_alerts, parse_eve_file
from rulescope.export import render_disable_conf
from rulescope.opnsense import render_opnsense_csv, render_opnsense_policy_json
from rulescope.pipeline import analyze_to_dict, build_catalog, load_profile, make_disable_conf, make_enable_conf
from rulescope.relevance import disable_candidates
from rulescope.store import catalog_summary, index_catalog, query_catalog

app = typer.Typer(
    name="rulescope",
    help="Open-source Suricata ruleset intelligence workbench",
    add_completion=False,
)


@app.command()
def analyze(
    rules: Path = typer.Argument(..., help="Rules file or directory"),
    profile: Optional[Path] = typer.Option(None, "--profile", "-p", help="Asset profile JSON"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write full JSON report"),
) -> None:
    """Enrich and score a ruleset against an asset profile."""
    prof = load_profile(profile)
    data = analyze_to_dict([rules], prof)
    summary = data["summary"]
    typer.echo(f"Rules: {summary['total_rules']} | CVE: {summary['with_cve']} | High+: {summary['high_severity']}")
    typer.echo(f"Relevance: {summary['by_relevance']}")
    typer.echo(f"Outdated candidates: {summary['outdated']}")
    if output:
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        typer.echo(f"Wrote {output}")


@app.command("export-disable")
def export_disable(
    rules: Path = typer.Argument(...),
    profile: Optional[Path] = typer.Option(None, "--profile", "-p"),
    output: Path = typer.Option(Path("disable.conf"), "--output", "-o"),
    max_score: float = typer.Option(30.0, "--max-score"),
) -> None:
    """Export suricata-update disable.conf candidates."""
    text = make_disable_conf([rules], load_profile(profile), max_score=max_score)
    output.write_text(text, encoding="utf-8")
    typer.echo(f"Wrote {output}")


@app.command("export-enable")
def export_enable(
    rules: Path = typer.Argument(...),
    profile: Optional[Path] = typer.Option(None, "--profile", "-p"),
    output: Path = typer.Option(Path("enable.conf"), "--output", "-o"),
    min_score: float = typer.Option(70.0, "--min-score"),
) -> None:
    """Export suricata-update enable.conf keepers."""
    text = make_enable_conf([rules], load_profile(profile), min_score=min_score)
    output.write_text(text, encoding="utf-8")
    typer.echo(f"Wrote {output}")


@app.command()
def diff(
    old_rules: Path = typer.Argument(..., help="Previous rules file/dir"),
    new_rules: Path = typer.Argument(..., help="New rules file/dir"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Compare two rulesets by SID (added / removed / changed)."""
    old, _ = build_catalog([old_rules])
    new, _ = build_catalog([new_rules])
    result = diff_rulesets(old, new)
    summary = result.to_dict()["summary"]
    typer.echo(
        f"Added: {summary['added']} | Removed: {summary['removed']} | "
        f"Changed: {summary['changed']} | Unchanged: {summary['unchanged']}"
    )
    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        typer.echo(f"Wrote {output}")


@app.command("export-opnsense")
def export_opnsense(
    rules: Path = typer.Argument(...),
    profile: Optional[Path] = typer.Option(None, "--profile", "-p"),
    outdir: Path = typer.Option(Path("opnsense-out"), "--outdir", "-o"),
    max_score: float = typer.Option(30.0, "--max-score"),
) -> None:
    """Export OPNsense-oriented policy helpers (CSV, JSON, disable.conf)."""
    catalog, _ = build_catalog([rules], load_profile(profile))
    outdir.mkdir(parents=True, exist_ok=True)
    disable_path = outdir / "disable.conf"
    csv_path = outdir / "opnsense-review.csv"
    json_path = outdir / "opnsense-policy.json"
    disable_path.write_text(
        render_disable_conf(disable_candidates(catalog, max_score=max_score)),
        encoding="utf-8",
    )
    csv_path.write_text(render_opnsense_csv(catalog, max_disable_score=max_score), encoding="utf-8")
    json_path.write_text(
        render_opnsense_policy_json(catalog, max_disable_score=max_score),
        encoding="utf-8",
    )
    typer.echo(f"Wrote {disable_path}")
    typer.echo(f"Wrote {csv_path}")
    typer.echo(f"Wrote {json_path}")


@app.command()
def index(
    rules: Path = typer.Argument(..., help="Rules file or directory"),
    db: Path = typer.Option(Path("rulescope.db"), "--db", help="SQLite catalog path"),
    profile: Optional[Path] = typer.Option(None, "--profile", "-p"),
) -> None:
    """Index an enriched/scored catalog into SQLite for fast querying."""
    summary = index_catalog(db, [rules], load_profile(profile))
    typer.echo(f"Indexed {summary['total_rules']} rules into {db}")


@app.command()
def query(
    db: Path = typer.Option(Path("rulescope.db"), "--db"),
    q: Optional[str] = typer.Option(None, "--q", help="Search msg/SID/CVE"),
    severity: Optional[str] = typer.Option(None, "--severity"),
    relevance: Optional[str] = typer.Option(None, "--relevance"),
    limit: int = typer.Option(20, "--limit"),
) -> None:
    """Query a previously indexed SQLite catalog."""
    summary = catalog_summary(db)
    typer.echo(f"Catalog rows: {summary.get('indexed_rows', summary.get('total_rules', 0))}")
    for rule in query_catalog(db, q=q, severity=severity, relevance=relevance, limit=limit):
        typer.echo(
            f"{rule.sid} [{rule.severity}/{rule.relevance_label} {rule.relevance_score}] {rule.msg}"
        )


@app.command()
def eve(
    eve_path: Path = typer.Argument(..., help="EVE JSON / NDJSON file"),
    rules: Path = typer.Option(..., "--rules", "-r"),
    profile: Optional[Path] = typer.Option(None, "--profile", "-p"),
    limit: int = typer.Option(20, "--limit"),
) -> None:
    """Correlate EVE alerts with enriched rules."""
    catalog, _ = build_catalog([rules], load_profile(profile))
    views = correlate_alerts(parse_eve_file(eve_path), catalog)[:limit]
    for view in views:
        rel = view.rule.relevance_label if view.rule else "?"
        score = view.rule.relevance_score if view.rule else "?"
        typer.echo(
            f"{view.timestamp} sid={view.signature_id} rel={rel}/{score} "
            f"{view.src_ip}:{view.src_port} -> {view.dest_ip}:{view.dest_port} | {view.signature}"
        )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Start the RuleScope web workbench."""
    uvicorn.run("rulescope.api:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
