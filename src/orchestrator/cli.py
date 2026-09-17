"""Entry point: `uv run scopeguard run --scope <path> [--profile <name>] [--log-level <level>]`."""

from __future__ import annotations

import argparse
import asyncio

from orchestrator.logging_config import configure_logging
from orchestrator.run import start_run


def main() -> None:
    parser = argparse.ArgumentParser(prog="scopeguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Start a scan run from a scope record")
    run_parser.add_argument("--scope", required=True, help="Path to the scope record YAML file")
    run_parser.add_argument(
        "--profile",
        default="recon_only",
        help="Scan profile from config/scan_profiles.yaml (default: recon_only)",
    )
    run_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Console log verbosity (default: INFO). DEBUG also shows rate-limit delays and authorization detail.",
    )

    args = parser.parse_args()

    if args.command == "run":
        configure_logging(args.log_level)
        run_id = asyncio.run(start_run(args.scope, args.profile))
        print(f"run started: {run_id}")


if __name__ == "__main__":
    main()
