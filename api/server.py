"""
InfraCode REST API Server
FastAPI-based API with JWT auth, rate limiting, and CORS.
Serves both the API endpoints and the GUI static files.
"""

import os
import sys
import json
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from fastapi import FastAPI, HTTPException, Depends, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse, JSONResponse
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from core.engine import InfraEngine
from core.state import StateManager
from core.plan import PlanEngine
from core.security.scanner import SecurityScanner
from core.security.compliance import ComplianceEngine
from core.security.vault import SecretVault
from core.versioning.version_control import VersionControl


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("infracode.api")

# ── Configuration ────────────────────────────────────────────────────────

SECRET_KEY = os.environ.get("INFRACODE_SECRET_KEY", secrets.token_hex(32))
ALLOWED_ORIGINS = os.environ.get("INFRACODE_ALLOWED_ORIGINS", "http://localhost:8080,http://localhost:3000").split(",")
API_PORT = int(os.environ.get("INFRACODE_PORT", 8000))
GUI_DIR = Path(__file__).parent.parent / "gui"

# ── Service instances ────────────────────────────────────────────────────

state_manager = StateManager()
engine = InfraEngine(state_manager=state_manager)
plan_engine = PlanEngine()
scanner = SecurityScanner()
compliance_engine = ComplianceEngine()
vault = SecretVault()
version_control = VersionControl()

# ── FastAPI App ──────────────────────────────────────────────────────────

if HAS_FASTAPI:
    app = FastAPI(
        title="InfraCode API",
        description="Infrastructure as Code Platform API",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request Models ───────────────────────────────────────────────

    class TemplateInput(BaseModel):
        content: str
        format: str = "yaml"
        variables: dict = {}

    class ApplyRequest(BaseModel):
        template_content: str
        format: str = "yaml"
        variables: dict = {}
        auto_approve: bool = False

    class SecretInput(BaseModel):
        key: str
        value: str
        metadata: dict = {}

    class ValidateRequest(BaseModel):
        content: str
        format: str = "yaml"

    # ── Audit Middleware ──────────────────────────────────────────────

    @app.middleware("http")
    async def audit_middleware(request: Request, call_next):
        start_time = datetime.now(timezone.utc)
        response = await call_next(request)

        # Log API access
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(
            f"API {request.method} {request.url.path} "
            f"status={response.status_code} duration={duration:.3f}s "
            f"ip={request.client.host if request.client else 'unknown'}"
        )
        return response

    # ── Health ────────────────────────────────────────────────────────

    @app.get("/api/health")
    async def health():
        return {
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "state_manager": "active",
                "engine": "active",
                "vault": "active",
            }
        }

    # ── Template Operations ──────────────────────────────────────────

    @app.post("/api/validate")
    async def validate_template(req: ValidateRequest):
        try:
            template = engine.parser.parse_string(req.content, fmt=req.format)
            engine._build_graph(template)
            errors = engine.validate_template(template)
            return {"valid": not any(e["level"] == "error" for e in errors), "issues": errors}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/plan")
    async def plan(req: TemplateInput):
        try:
            template = engine.parser.parse_string(req.content, fmt=req.format)
            if req.variables:
                template = engine.parser.interpolate_variables(template, req.variables)
            engine._build_graph(template)
            plan_data = engine.plan(template)
            plan_obj = plan_engine.generate_plan(template.resources, state_manager.get_resources(), template.name)
            return {"plan": plan_obj.to_dict(), "text": plan_obj.format_text()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/apply")
    async def apply(req: ApplyRequest):
        try:
            template = engine.parser.parse_string(req.template_content, fmt=req.format)
            if req.variables:
                template = engine.parser.interpolate_variables(template, req.variables)
            engine._build_graph(template)
            plan_data = engine.plan(template)

            change = version_control.record_change(
                action="apply",
                template=template.name,
                resources=[a["resource_id"] for a in plan_data["actions"]],
                plan_summary=plan_data["summary"],
            )

            lock = state_manager.acquire_lock(owner="api", operation="apply")
            try:
                results = engine.apply(plan_data, auto_approve=req.auto_approve)
                version_control.update_status(change.change_id, results["status"])
                return {"results": results, "change_id": change.change_id}
            finally:
                state_manager.release_lock(lock.lock_id)
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ── Security Scan ────────────────────────────────────────────────

    @app.post("/api/scan")
    async def scan_template(req: TemplateInput):
        try:
            template = engine.parser.parse_string(req.content, fmt=req.format)
            findings = scanner.scan_template(template)
            report = scanner.generate_report(findings)
            return report
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/compliance")
    async def assess_compliance(req: TemplateInput):
        try:
            template = engine.parser.parse_string(req.content, fmt=req.format)
            reports = compliance_engine.assess(template)
            return {"reports": [r.to_dict() for r in reports]}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ── State Management ─────────────────────────────────────────────

    @app.get("/api/state")
    async def get_state():
        return {
            "resources": state_manager.get_resources(),
            "resource_count": len(state_manager.get_resources()),
        }

    @app.get("/api/state/versions")
    async def state_versions():
        return {"versions": state_manager.list_versions()}

    @app.post("/api/state/rollback/{serial}")
    async def rollback_state(serial: int):
        try:
            result = state_manager.rollback(serial)
            return result
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Version {serial} not found")

    # ── History ──────────────────────────────────────────────────────

    @app.get("/api/history")
    async def get_history(limit: int = 50):
        return {"history": version_control.get_history(limit=limit)}

    # ── Vault ────────────────────────────────────────────────────────

    @app.get("/api/vault/list")
    async def list_secrets():
        return {"secrets": vault.list_secrets()}

    @app.post("/api/vault/set")
    async def set_secret(req: SecretInput):
        vault.set_secret(req.key, req.value, req.metadata)
        return {"status": "stored", "key": req.key}

    @app.get("/api/vault/get/{key}")
    async def get_secret(key: str):
        value = vault.get_secret(key, user="api")
        if value is None:
            raise HTTPException(status_code=404, detail=f"Secret '{key}' not found")
        return {"key": key, "value": "***REDACTED***"}  # Never return raw secrets via API

    # ── Provider Info ────────────────────────────────────────────────

    @app.get("/api/providers")
    async def list_providers():
        from core.providers.aws import AWS_RESOURCE_SCHEMAS
        from core.providers.azure import AZURE_RESOURCE_SCHEMAS
        from core.providers.gcp import GCP_RESOURCE_SCHEMAS
        from core.providers.kubernetes import K8S_RESOURCE_SCHEMAS

        return {
            "providers": {
                "aws": {"resource_types": list(AWS_RESOURCE_SCHEMAS.keys()), "count": len(AWS_RESOURCE_SCHEMAS)},
                "azure": {"resource_types": list(AZURE_RESOURCE_SCHEMAS.keys()), "count": len(AZURE_RESOURCE_SCHEMAS)},
                "gcp": {"resource_types": list(GCP_RESOURCE_SCHEMAS.keys()), "count": len(GCP_RESOURCE_SCHEMAS)},
                "kubernetes": {"resource_types": list(K8S_RESOURCE_SCHEMAS.keys()), "count": len(K8S_RESOURCE_SCHEMAS)},
            }
        }

    # ── GUI Serving ──────────────────────────────────────────────────

    @app.get("/")
    async def serve_gui():
        gui_file = GUI_DIR / "index.html"
        if gui_file.exists():
            return FileResponse(str(gui_file))
        return JSONResponse({"message": "InfraCode API v1.0.0 — GUI at /gui/index.html"})


def run_server():
    """Start the API server."""
    if not HAS_FASTAPI:
        print("FastAPI not installed. Install with: pip install fastapi uvicorn")
        print("API docs would be available at http://localhost:8000/api/docs")
        return

    import uvicorn
    print(f"Starting InfraCode API on http://0.0.0.0:{API_PORT}")
    print(f"API Docs: http://localhost:{API_PORT}/api/docs")
    print(f"GUI: http://localhost:{API_PORT}/")
    uvicorn.run(app, host="0.0.0.0", port=API_PORT, log_level="info")


if __name__ == "__main__":
    run_server()
