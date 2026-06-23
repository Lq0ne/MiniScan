# -*- coding: utf-8 -*-
"""
CLI argument parser for MiniScan.

Keeping argument parsing isolated here means the rest of the codebase
never touches `sys.argv` directly, and `args` is passed explicitly
rather than stored as a global.
"""
import argparse
import logging
import sys

logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace with all parsed flags plus a derived `mode` string
        ('scan-all' | 'monitor' | 'testing').

    Exits with code 1 on validation errors.
    """
    try:
        parser = argparse.ArgumentParser(
            description="MiniScan: WeChat Mini Program decompiler and security auditor"
        )

        # Mutually exclusive primary modes
        mode_group = parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument(
            "--scan-all",
            dest="scan_all",
            action="store_true",
            help="Scan all existing decompiled mini program sources under Output/Source using Fortify only",
        )
        mode_group.add_argument(
            "--monitor",
            dest="monitor",
            action="store_true",
            help=(
                "Monitor WeChat mini program windows, decompile in real time, "
                "run local analysis and Fortify scan"
            ),
        )
        mode_group.add_argument(
            "--testing",
            dest="testing",
            action="store_true",
            help=(
                "Monitor WeChat mini program windows and decompile in real time, "
                "run local analysis only (no Fortify scan)"
            ),
        )

        # Global options
        parser.add_argument(
            "-hook",
            "--hook",
            dest="devtools_hook",
            action="store_true",
            help="Enable Frida hook and open DevTools (only valid with --testing)",
        )

        # Monitor-mode options
        parser.add_argument(
            "--rate",
            "--thread",
            dest="rate",
            type=int,
            default=2,
            help="[monitor only] batch decompile concurrency (default: 2). Alias: --thread",
        )

        args = parser.parse_args()

        # Derive a simple mode string for downstream logic
        if args.scan_all:
            args.mode = "scan-all"
        elif args.monitor:
            args.mode = "monitor"
        elif args.testing:
            args.mode = "testing"
        else:
            args.mode = "unknown"

        # Cross-option validation
        if args.devtools_hook and args.mode != "testing":
            logger.error("--hook can only be used together with --testing mode")
            print("ERROR: --hook can only be used together with --testing mode")
            sys.exit(1)

        if args.rate != 2 and args.mode != "monitor":
            logger.error("--rate/--thread can only be used together with --monitor mode")
            print("ERROR: --rate/--thread can only be used together with --monitor mode")
            sys.exit(1)

        return args

    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"parse_arguments error: {e}")
        sys.exit(1)
