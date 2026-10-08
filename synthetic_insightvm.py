"""Small local InsightVM API emulator for testing the patch automation worker.

The emulator implements the report lifecycle used by worker/patch-auto.py:

    POST /api/3/reports/{report_id}/generate
    GET  /api/3/reports/{report_id}/history/{instance_id}
    GET  /api/3/reports/{report_id}/history/{instance_id}/output

It is intentionally dependency-free and serves only local synthetic data.
"""

from __future__ import annotations

import argparse
import json
import threading
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = ROOT / "synthetic_insightvm_data"


class InsightVMMockHandler(BaseHTTPRequestHandler):
    server_version = "SyntheticInsightVM/1.0"

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, payload: dict[str, str]) -> None:
        self._send(
            status,
            json.dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        path = [unquote(part) for part in urlparse(self.path).path.split("/") if part]

        if path == ["health"]:
            self._json(HTTPStatus.OK, {"status": "ok"})
            return

        if (
            len(path) == 7
            and path[:3] == ["api", "3", "reports"]
            and path[4] == "history"
            and path[6] == "output"
        ):
            report_id, instance_id = path[3], path[5]
            if not self._known_instance(report_id, instance_id):
                return

            csv_path = self.server.data_dir / f"{report_id}.csv"
            if not csv_path.is_file():
                self._json(
                    HTTPStatus.NOT_FOUND,
                    {"error": f"No synthetic fixture for report ID {report_id}"},
                )
                return
            self._send(HTTPStatus.OK, csv_path.read_bytes(), "text/csv; charset=utf-8")
            return

        if (
            len(path) == 6
            and path[:3] == ["api", "3", "reports"]
            and path[4] == "history"
        ):
            report_id, instance_id = path[3], path[5]
            if self._known_instance(report_id, instance_id):
                self._json(HTTPStatus.OK, {"status": "complete"})
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown endpoint"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        path = [unquote(part) for part in urlparse(self.path).path.split("/") if part]

        if len(path) == 5 and path[:3] == ["api", "3", "reports"] and path[4] == "generate":
            report_id = path[3]
            csv_path = self.server.data_dir / f"{report_id}.csv"
            if not csv_path.is_file():
                self._json(
                    HTTPStatus.NOT_FOUND,
                    {"error": f"No synthetic fixture for report ID {report_id}"},
                )
                return

            instance_id = f"synthetic-{report_id}-{uuid.uuid4().hex[:12]}"
            with self.server.instances_lock:
                self.server.instances[instance_id] = report_id
            self._json(HTTPStatus.OK, {"id": instance_id})
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown endpoint"})

    def _known_instance(self, report_id: str, instance_id: str) -> bool:
        with self.server.instances_lock:
            known_report_id = self.server.instances.get(instance_id)
        if known_report_id != report_id:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown report instance"})
            return False
        return True

    def log_message(self, format: str, *args: object) -> None:
        print(f"[synthetic-insightvm] {format % args}")


class InsightVMMockServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], data_dir: Path):
        super().__init__(address, InsightVMMockHandler)
        self.data_dir = data_dir
        self.instances: dict[str, str] = {}
        self.instances_lock = threading.Lock()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    args = parser.parse_args()

    data_dir = args.data_dir.resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    server = InsightVMMockServer((args.host, args.port), data_dir)
    print(f"Synthetic InsightVM listening at http://{args.host}:{args.port}")
    print(f"Serving fixtures from {data_dir}")
    print("Available report IDs:", ", ".join(sorted(p.stem for p in data_dir.glob("*.csv"))))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping synthetic InsightVM")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
