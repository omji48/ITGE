"""
FastAPI surface for ITGE integrations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ..cli.config import ITGEConfig


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "itge"


class AnalysisSummary(BaseModel):
    total_paths_found: int
    avg_path_length: float
    avg_risk_score: float
    max_risk_score: float
    computation_time_ms: float
    top_paths: list[dict[str, Any]] = Field(default_factory=list)


def create_app(config: ITGEConfig) -> FastAPI:
    app = FastAPI(
        title="ITGE API",
        version="0.1.0",
        description="Identity & Trust Graph Engine service API",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse()

    @app.get("/config")
    async def show_config() -> dict[str, Any]:
        return {
            "neo4j_uri": config.neo4j_uri,
            "neo4j_user": config.neo4j_user,
            "output_dir": str(config.output_dir),
            "default_max_hops": config.default_max_hops,
            "default_max_paths": config.default_max_paths,
        }

    @app.get("/analysis/latest", response_model=AnalysisSummary)
    async def latest_analysis() -> AnalysisSummary:
        result_file = config.output_dir / "analysis_result.json"
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="No analysis has been exported yet.")

        data = json.loads(result_file.read_text(encoding="utf-8"))
        return AnalysisSummary(
            total_paths_found=data["total_paths_found"],
            avg_path_length=data["avg_path_length"],
            avg_risk_score=data["avg_risk_score"],
            max_risk_score=data["max_risk_score"],
            computation_time_ms=data["computation_time_ms"],
            top_paths=data.get("highest_risk_paths", [])[:5],
        )

    @app.get("/export/json")
    async def export_json():
        result_file = config.output_dir / "analysis_result.json"
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="No report found.")
        return FileResponse(
            path=result_file,
            filename="itge_analysis.json",
            media_type="application/json"
        )

    @app.get("/export/markdown")
    async def export_markdown():
        # Check both potential filenames
        for fname in ["report.md", "analysis_result.md"]:
            report_file = config.output_dir / fname
            if report_file.exists():
                return FileResponse(
                    path=report_file,
                    filename="itge_analysis.md",
                    media_type="text/markdown"
                )
        raise HTTPException(status_code=404, detail="No markdown report found.")

    return app
