"""FastAPI application for RuleScope workbench."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from rulescope.eve import correlate_alerts, parse_eve_file
from rulescope.export import render_disable_conf, render_enable_conf
from rulescope.models import AssetProfile
from rulescope.pipeline import build_catalog
from rulescope.relevance import disable_candidates

WEB_DIR = Path(__file__).parent / "web"
SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"

app = FastAPI(
    title="RuleScope",
    description="Open-source Suricata ruleset intelligence workbench",
    version="0.1.0",
)


class AnalyzeRequest(BaseModel):
    rules_text: str = Field(..., min_length=1)
    profile: AssetProfile = Field(default_factory=AssetProfile)


class EveRequest(BaseModel):
    eve_text: str
    rules_text: str
    profile: AssetProfile = Field(default_factory=AssetProfile)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "project": "rulescope", "version": "0.1.0"}


@app.get("/api/sample/rules")
def sample_rules() -> PlainTextResponse:
    path = SAMPLES_DIR / "rules" / "demo.rules"
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@app.get("/api/sample/profile")
def sample_profile() -> dict:
    path = SAMPLES_DIR / "profiles" / "homelab.json"
    return AssetProfile.model_validate_json(path.read_text(encoding="utf-8")).model_dump()


@app.get("/api/sample/eve")
def sample_eve() -> PlainTextResponse:
    path = SAMPLES_DIR / "eve" / "eve-alerts.json"
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "input.rules"
        rules_path.write_text(req.rules_text, encoding="utf-8")
        rules, summary = build_catalog([rules_path], req.profile)
    return {
        "summary": summary.model_dump(mode="json"),
        "profile": req.profile.model_dump(mode="json"),
        "rules": [r.model_dump(mode="json") for r in rules],
    }


@app.post("/api/export/disable", response_class=PlainTextResponse)
def export_disable(req: AnalyzeRequest, max_score: float = 30.0) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "input.rules"
        rules_path.write_text(req.rules_text, encoding="utf-8")
        rules, _ = build_catalog([rules_path], req.profile)
    return render_disable_conf(disable_candidates(rules, max_score=max_score))


@app.post("/api/export/enable", response_class=PlainTextResponse)
def export_enable(req: AnalyzeRequest, min_score: float = 70.0) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "input.rules"
        rules_path.write_text(req.rules_text, encoding="utf-8")
        rules, _ = build_catalog([rules_path], req.profile)
    keep = [r for r in rules if r.relevance_score >= min_score]
    return render_enable_conf(keep)


@app.post("/api/eve")
def eve_correlate(req: EveRequest) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "input.rules"
        eve_path = Path(tmp) / "eve.json"
        rules_path.write_text(req.rules_text, encoding="utf-8")
        eve_path.write_text(req.eve_text, encoding="utf-8")
        rules, summary = build_catalog([rules_path], req.profile)
        views = correlate_alerts(parse_eve_file(eve_path), rules)
    return {
        "summary": summary.model_dump(mode="json"),
        "alerts": [v.model_dump(mode="json") for v in views],
    }


@app.post("/api/upload/analyze")
async def upload_analyze(
    rules_file: UploadFile = File(...),
    profile_json: str = Form("{}"),
) -> dict:
    try:
        profile = AssetProfile.model_validate_json(profile_json or "{}")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Invalid profile JSON: {exc}") from exc
    text = (await rules_file.read()).decode("utf-8", errors="replace")
    return analyze(AnalyzeRequest(rules_text=text, profile=profile))


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
