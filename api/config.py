# paths, env

import os
from pathlib import Path
from dotenv import load_dotenv

WORKER_DIR = Path(__file__).resolve().parent.parent
load_dotenv(WORKER_DIR / ".env")

RUNS_DIR = Path(os.getenv("RUNS_DIR", WORKER_DIR / "runs")).resolve()
WORKER_SCRIPT = WORKER_DIR / "patch-auto.py"
API_KEY = os.getenv("PATCH_API_KEY", "")
RUNS_DIR.mkdir(parents=True, exist_ok=True)