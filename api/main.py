# FastAPI app + routes
import json
from contextlib import asynccontextmanager
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, field_validator
from . import run_manager as rm
from .security import require_key


@asynccontextmanager
async def lifespan(_):
    rm.recover_orphans()
    yield


app = FastAPI(title="PatchFlow Automation API", lifespan=lifespan)
api = APIRouter(
    prefix="/api",
    dependencies=[Depends(require_key)]
    )


class StartRun(BaseModel):
    reports: list[str] | None = None
    dry_run: bool = False

    @field_validator("reports")
    @classmethod
    def digits_only(cls, v):
        if v and not all(r.isdigit() for r in v):
            raise ValueError("report ids must be numeric")
        return v

#==========================================
#Overall status endpoints
#=========================================
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "PatchFlow Automation API",
        "message": "FastAPI backend is running"
    }
    
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "PatchFlow Automation API",
        "active_run": rm.active_run_id()
        }

#==========================================
#Protected endpoints below
#==========================================
@app.post("/runs", status_code=202)
def create_run(body: StartRun, x_actor: str = Header(default="unknown")):
    try:
        return rm.start_run(body.reports, body.dry_run, x_actor)
    except rm.RunInProgress:
        raise HTTPException(409, "A run is already in progress")


@app.get("/runs")
def runs():
    return rm.list_runs()


@app.get("/runs/{run_id}")
def run(run_id: str):
    meta = rm.read_meta(run_id)
    if not meta:
        raise HTTPException(404)
    return meta


@app.get("/runs/{run_id}/stream")
def stream(run_id: str):
    if not rm.read_meta(run_id):
        raise HTTPException(404)
    return StreamingResponse(
        rm.stream_log(run_id), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/runs/{run_id}/cancel")
def cancel(run_id: str):
    if not rm.cancel_run(run_id):
        raise HTTPException(409, "Run is not active")
    return {"ok": True}


@app.get("/runs/{run_id}/summary")
def summary(run_id: str):
    p = rm.run_dir(run_id) / "summary.json"
    if not p.exists():
        raise HTTPException(404, "No summary yet")
    return json.loads(p.read_text())


@app.get("/runs/{run_id}/files")
def files(run_id: str):
    d = rm.run_dir(run_id)
    return [str(p.relative_to(d)).replace("\\", "/")
            for p in d.rglob("*")
            if p.is_file() and p.name not in {"meta.json", "meta.json.tmp"}]


@app.get("/runs/{run_id}/files/{path:path}")
def file(run_id: str, path: str):
    d = rm.run_dir(run_id).resolve()
    target = (d / path).resolve()
    if not target.is_relative_to(d) or not target.is_file():
        raise HTTPException(404)
    return FileResponse(target)


app.include_router(api)