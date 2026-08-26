from __future__ import annotations

import argparse
import json

from fraudshield.core.config import Settings
from fraudshield.services.container import ServiceContainer
from fraudshield.worker import DurableWorker


def main() -> None:
    parser = argparse.ArgumentParser(description="FraudShield backend utilities")
    subcommands = parser.add_subparsers(dest="command", required=True)
    serve = subcommands.add_parser("serve", help="Run the API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8000, type=int)
    subcommands.add_parser("init-db", help="Initialize the configured database schema")
    subcommands.add_parser("cleanup-db", help="Safely clean legacy synthetic demo records from database")
    worker = subcommands.add_parser("worker", help="Run the durable analysis worker")
    worker.add_argument("--once", action="store_true", help="Process at most one queued job")
    worker.add_argument("--worker-id", default=None)
    args = parser.parse_args()

    if args.command == "serve":
        import uvicorn

        runtime_settings = Settings.from_env()
        runtime_settings.validate()
        uvicorn.run(
            "fraudshield.main:app",
            host=args.host,
            port=args.port,
            proxy_headers=True,
            forwarded_allow_ips=runtime_settings.forwarded_allow_ips,
            server_header=False,
            timeout_keep_alive=5,
        )
        return
    settings = Settings.from_env()
    settings.ensure_directories()
    settings.validate()
    services = ServiceContainer.build(settings)
    if args.command == "init-db":
        print(json.dumps({"status": "initialized", "database_backend": services.db.backend}))
        services.db.close()
        return
    if args.command == "cleanup-db":
        results = services.analyses.cleanup_synthetic_records()
        print(json.dumps({"status": "cleanup_completed", **results}))
        services.db.close()
        return
    if args.command == "worker":
        durable_worker = DurableWorker(services, worker_id=args.worker_id)
        if args.once:
            processed = durable_worker.process_next()
            print(json.dumps({"status": "processed" if processed else "idle"}))
            services.db.close()
            return
        try:
            durable_worker.run_forever()
        finally:
            services.db.close()
        return
    services.db.close()


if __name__ == "__main__":
    main()
