# spawn, lock, cancel, tail log, history

import json, os, re, subprocess, sys, threading, time
from datetime import datetime, timezone
from pathlib import Path
from .config import RUNS_DIR, WORKER_SCRIPT

RUN_ID_RE = re.compile(r"^RUN-\d{8}-\d{6}$")
_lock = threading.Lock()
_procs: dict[str, subprocess.Popen] = {}


class RunInProgress(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_dir(run_id: str) -> Path:
    if not RUN_ID_RE.match(run_id):
        raise ValueError("bad run id")
    return RUNS_DIR / run_id


def read_meta(run_id: str) -> dict | None:
    p = run_dir(run_id) / "meta.json"
    return json.loads(p.read_text()) if p.exists() else None


def write_meta(run_id: str, meta: dict):
    d = run_dir(run_id)
    tmp = d / "meta.json.tmp"
    tmp.write_text(json.dumps(meta, indent=2))
    os.replace(tmp, d / "meta.json")          # atomic


def active_run_id() -> str | None:
    for rid, p in _procs.items():
        if p.poll() is None:
            return rid
    return None


def start_run(reports: list[str] | None, dry_run: bool, actor: str) -> dict:
    with _lock:
        if active_run_id():
            raise RunInProgress()

        run_id = datetime.now().strftime("RUN-%Y%m%d-%H%M%S")
        d = RUNS_DIR / run_id
        d.mkdir(parents=True)

        env = {
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",      # Windows console safety
            "DRY_RUN": "1" if dry_run else "0",
        }
        if reports:
            env["PATCH_REPORT_IDS"] = ",".join(reports)
        if dry_run:
            env["EMAIL_MODE"] = "file"

        log = open(d / "run.log", "ab")
        proc = subprocess.Popen(
            [sys.executable, "-u", str(WORKER_SCRIPT)],
            cwd=d, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        meta = {
            "id": run_id, "status": "running", "actor": actor,
            "dry_run": dry_run, "reports": reports or "default",
            "started_at": _now(), "ended_at": None, "exit_code": None,
            "cancel_requested": False,
        }
        write_meta(run_id, meta)
        _procs[run_id] = proc

    threading.Thread(target=_watch, args=(run_id, proc, log), daemon=True).start()
    return meta


def _watch(run_id, proc, log):
    code = proc.wait()
    log.close()
    meta = read_meta(run_id) or {}
    if meta.get("cancel_requested"):
        status = "cancelled"
    else:
        status = "completed" if code == 0 else "failed"
    meta.update(status=status, exit_code=code, ended_at=_now())
    write_meta(run_id, meta)


def cancel_run(run_id: str) -> bool:
    proc = _procs.get(run_id)
    if not proc or proc.poll() is not None:
        return False
    meta = read_meta(run_id) or {}
    meta["cancel_requested"] = True
    write_meta(run_id, meta)
    proc.terminate()
    return True


def list_runs(limit: int = 50) -> list[dict]:
    out = []
    for d in sorted(RUNS_DIR.glob("RUN-*"), reverse=True)[:limit]:
        m = read_meta(d.name)
        if m:
            out.append(m)
    return out


def recover_orphans():
    """Server restarted mid-run: mark those runs as interrupted."""
    for d in RUNS_DIR.glob("RUN-*"):
        m = read_meta(d.name)
        if m and m["status"] == "running" and d.name not in _procs:
            m.update(status="interrupted", ended_at=_now())
            write_meta(d.name, m)


def stream_log(run_id: str):
    """SSE generator: replays the file, then follows it until the process ends."""
    path = run_dir(run_id) / "run.log"
    pos, buf = 0, b""
    while True:
        proc = _procs.get(run_id)
        running = proc is not None and proc.poll() is None
        if path.exists():
            with open(path, "rb") as f:
                f.seek(pos)
                data = f.read()
                pos += len(data)
            buf += data
            *lines, buf = buf.split(b"\n")
            for line in lines:
                yield f"data: {line.decode('utf-8', 'replace').rstrip()}\n\n"
        if not running:
            if buf:
                yield f"data: {buf.decode('utf-8', 'replace').rstrip()}\n\n"
            meta = read_meta(run_id) or {}
            yield f"event: end\ndata: {meta.get('status', 'unknown')}\n\n"
            return
        yield ": ping\n\n"
        time.sleep(0.5)