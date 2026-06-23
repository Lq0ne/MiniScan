# -*- coding: utf-8 -*-
"""
MiniScan entry point.

Run with:
    python main.py --testing
    python main.py --testing --hook
    python main.py --monitor [--rate N]
    python main.py --scan-all
"""
import logging
import sys

import requests

from miniscan.cli import parse_arguments
from miniscan.config import setup_logging
from miniscan.scanner.fortify import main as fortify_main
from miniscan.wechat.tools import WxTools

# Suppress InsecureRequestWarning globally
requests.packages.urllib3.disable_warnings()

_BANNER = r"""
░█▄█░▀█▀░█▀█░▀█▀░░░█▀▀░█▀▀░█▀█░█▀█░░░█░█░▀█░░░░░▀█░
░█░█░░█░░█░█░░█░░░░▀▀█░█░░░█▀█░█░█░░░▀▄▀░░█░░░░░░█░
░▀░▀░▀▀▀░▀░▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░▀░▀░░░░▀░░▀▀▀░▀░░▀▀▀
  MiniScan_v1.1  Author: Lq0ne  Contributor: Xiaolin
  Mode: {mode}
"""


def main() -> None:
    # Parse first so logging is configured before any real work starts
    args = parse_arguments()
    setup_logging()

    logger = logging.getLogger(__name__)

    print(_BANNER.format(mode=args.mode.upper()))

    # ── scan-all mode: Fortify only, then exit ────────────────────────────
    if args.mode == "scan-all":
        logger.info(
            "Running in SCAN-ALL mode: scanning all projects under "
            "Output/Source with Fortify"
        )
        exit_code = fortify_main()
        sys.exit(exit_code)

    # ── Modes that require WeChat monitoring ──────────────────────────────
    wx_tools = WxTools(args)

    if args.mode in ("monitor", "testing"):
        print(
            "\n[WARNING] To detect mini programs that have been opened before, "
            "existing cache folders under wx_dir must be removed first.\n"
            "This will force WeChat to regenerate mini program packages on next launch.\n"
            "Do you want to clean existing mini program cache folders now? "
            "(they will be deleted recursively)\n"
        )
        choice = input(
            "Type 'Y' to proceed with cleanup, or anything else to skip: "
        ).strip().lower()
        if choice == "y":
            logger.info(
                "User confirmed wx_dir cleanup. "
                "Cleaning WeChat mini program cache folders..."
            )
            wx_tools.clean_wx_dirs()
            logger.info(
                "wx_dir cleanup finished. "
                "Existing mini program cache folders were removed."
            )
        elif args.mode == "monitor":
            sys.exit(0)

    logger.info(f"Mini-Scan initialized in mode: {args.mode}")

    # ── Main loop (each method contains its own while True) ───────────────
    if args.mode == "testing":
        wx_tools.run_testing_mode()
    elif args.mode == "monitor":
        wx_tools.run_monitor_mode()


if __name__ == "__main__":
    main()
