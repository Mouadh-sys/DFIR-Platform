#!/usr/bin/env python3
"""Serve a harmless local-only health endpoint for the DFIR network telemetry exercise.

This is deliberately not a command-and-control server: it supports GET /health only,
returns a fixed response, rejects all request bodies, and binds to the lab bridge IP.
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class HealthHandler(BaseHTTPRequestHandler):
    server_version = "DFIRLabHealth/1.0"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler callback name
        logger: logging.Logger = self.server.lab_logger  # type: ignore[attr-defined]
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        logger.info("time=%s src=%s:%s method=GET path=%s", timestamp, self.client_address[0], self.client_address[1], self.path)
        if self.path != "/health":
            self.send_error(404, "Only /health is available")
            return
        payload = json.dumps({"status": "ok", "service": "dfir-lab-health", "marker": "DFIR_LAB_CANARY_C01"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        self.send_error(405, "POST is not supported by this lab health service")

    def do_PUT(self) -> None:  # noqa: N802
        self.send_error(405, "PUT is not supported by this lab health service")

    def do_DELETE(self) -> None:  # noqa: N802
        self.send_error(405, "DELETE is not supported by this lab health service")

    def log_message(self, fmt: str, *args: object) -> None:
        # Use the configured lab log instead of stderr's default web-server format.
        logger: logging.Logger = self.server.lab_logger  # type: ignore[attr-defined]
        logger.info("http-log client=%s message=%s", self.client_address[0], fmt % args)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="10.10.10.1", help="Must be the host's lab bridge IP, not 0.0.0.0")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--log", type=Path, required=True, help="Host-side log path outside Git")
    args = parser.parse_args()
    if args.bind in {"0.0.0.0", "::"}:
        parser.error("Refusing wildcard bind; bind to the lab bridge IP only")
    if not (1 <= args.port <= 65535):
        parser.error("port must be between 1 and 65535")

    args.log.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dfir-lab-health")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(message)s")
    handler = logging.FileHandler(args.log, encoding="utf-8")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.addHandler(logging.StreamHandler())

    server = ThreadingHTTPServer((args.bind, args.port), HealthHandler)
    server.lab_logger = logger  # type: ignore[attr-defined]
    print(f"DFIR health endpoint listening at http://{args.bind}:{args.port}/health")
    print("Only GET /health is served; no command execution or uploads are implemented. Ctrl-C to stop.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("Stopping health endpoint")
    finally:
        server.server_close()
        for log_handler in logger.handlers[:]:
            log_handler.close()
            logger.removeHandler(log_handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
