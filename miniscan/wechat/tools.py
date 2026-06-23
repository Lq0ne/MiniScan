# -*- coding: utf-8 -*-
"""
WeChat mini program cache management and decompilation.

The WxTools class drives two operating modes:
  - run_testing_mode()  : immediately decompile each new mini program as it
                          appears (no Fortify scan, optional Frida hook).
  - run_monitor_mode()  : queue new mini programs until the user types
                          'start', then batch-decompile with concurrency and
                          run a Fortify SAST scan.

Refactoring notes (vs. the original Mini-Scan.py):
  - Previously nested helper functions (input_worker, if_main_apkg, worker)
    are now proper private methods of WxTools.
  - CLI args are passed in via the constructor (self.args) instead of being
    read from a module-level global.
  - The combined monitor_mode_monitor(testingTag=...) entry point is split
    into two clearly named public methods.
"""
import argparse
import logging
import os
import random
import shutil
import string
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep

from miniscan.config import Config
from miniscan.scanner.file_processor import FileProcessor
from miniscan.scanner.fortify import main as fortify_main
from miniscan.wechat.hook import run_wechat_hook, WxHook
from miniscan.utils.path_utils import get_tools_path, ensure_dir_exists

logger = logging.getLogger(__name__)


class WxTools:
    """Manages the WeChat mini program cache directory and orchestrates decompilation."""

    def __init__(self, args: argparse.Namespace) -> None:
        """
        Args:
            args: Parsed CLI arguments from miniscan.cli.parse_arguments().
                  Must expose at least: args.devtools_hook, args.rate.
        """
        self.args = args

        wx_dir = Config().wx_dir
        if not wx_dir:
            logger.error("wx_dir is not configured in config.yaml (mini_scan.wx_dir)")
            sys.exit(0)

        self.applet_dir: str = wx_dir
        self.unpack_tool: str = get_tools_path("KillWxapkg.exe")
        # Tracks dirs observed by _detect_new_cache_dirs across consecutive calls
        self._seen_cache_dirs: set = set()

    # -----------------------------------------------------------------------
    # Public mode runners
    # -----------------------------------------------------------------------

    def run_testing_mode(self) -> None:
        """
        --testing mode main loop.

        Detect new mini programs continuously.  Each new program is
        decompiled immediately (blocking further detection), then optionally
        hooked via Frida.  Fortify scan is never triggered in this mode.
        """
        logger.info("Testing mode initialized. Watching for new mini programs...")
        
        try:
            before: set = {
                entry.name
                for entry in os.scandir(self.applet_dir)
                if entry.is_dir()
            }
        except Exception as e:
            logger.error(f"Failed to read existing cache directories: {e}")
            before: set = set()

        while True:
            new_folders = self._detect_new_cache_dirs(before)
            for folder in new_folders:
                if self._has_main_wxapkg(folder):
                    title = self._safe_mini_title()
                    before.add(folder)
                    logger.info(f"[Testing] Decompiling \"{title}\" immediately...")
                    ok, _ = self._decompile_and_local_scan(folder, title, log_verbose=True)
                    if ok:
                        logger.info(f"[Testing] Decompile finished: \"{title}\"")
                        if self.args.devtools_hook:
                            threading.Thread(
                                target=run_wechat_hook, daemon=True
                            ).start()
                    else:
                        logger.error(f"[Testing] Decompile failed: \"{title}\"")

    def run_monitor_mode(self) -> None:
        """
        --monitor mode main loop.

        Detect new mini programs and add them to a pending queue.
        When the user types 'start' on stdin, batch-decompile all queued
        programs (with concurrency = args.rate) and then trigger a
        Fortify SAST scan.
        """
        pending: dict = {}            # folder -> title
        pending_lock = threading.Lock()
        start_event = threading.Event()
        exit_event = threading.Event()
        
        try:
            before: set = {
                entry.name
                for entry in os.scandir(self.applet_dir)
                if entry.is_dir()
            }
        except Exception as e:
            logger.error(f"Failed to read existing cache directories: {e}")
            before: set = set()

        # Background thread listens for the 'start' command on stdin
        threading.Thread(
            target=self._input_worker_thread,
            args=(start_event, exit_event),
            daemon=True,
        ).start()

        logger.info(
            "Monitor mode initialized. "
            "Watching new mini programs. Type 'start' to batch decompile, 'exit' to quit."
        )

        while not exit_event.is_set():
            # ── Phase 1: collect new folders ─────────────────────────────
            try:
                new_folders = self._detect_new_cache_dirs(before)
                if new_folders:
                    with pending_lock:
                        for folder in new_folders:
                            if folder not in pending and self._has_main_wxapkg(folder):
                                title = self._safe_mini_title()
                                pending[folder] = title
                                before.add(folder)
                                logger.info(
                                    f"Detected new mini program \"{title}\" "
                                    f"(queued). Pending: {len(pending)}"
                                )
            except Exception as e:
                logger.error(f"Monitor mode collect error: {e}")

            # ── Phase 2: process on 'start' ───────────────────────────────
            if not start_event.is_set():
                continue

            with pending_lock:
                batch = dict(pending)
                pending.clear()
            start_event.clear()

            if not batch:
                logger.info("No pending mini programs detected. Continue monitoring...")
                continue

            rate = max(1, getattr(self.args, "rate", 2) or 2)
            logger.info(f"Start batch decompile: total={len(batch)}, rate={rate}")

            results = []
            with ThreadPoolExecutor(max_workers=rate) as executor:
                futures = {
                    executor.submit(self._decompile_worker, f, t): (f, t)
                    for f, t in batch.items()
                }
                for future in as_completed(futures):
                    try:
                        folder, title, ok, out_dir = future.result()
                        results.append((folder, title, ok, out_dir))
                        if ok:
                            logger.info(f"Decompile+local scan finished: \"{title}\"")
                        else:
                            logger.error(f"Decompile/local scan failed: \"{title}\"")
                    except Exception as e:
                        logger.error(f"Batch task exception: {e}")

            # ── Fortify scan (once per batch) ─────────────────────────────
            logger.info(
                "Monitor mode: triggering Fortify scan for all projects "
                "under Output/Source"
            )
            try:
                fortify_main()
                logger.info("Fortify scan finished!")
                logger.info("Back to monitor mode, continue monitoring...")
            except Exception as e:
                logger.error(f"Fortify scan failed in monitor mode: {e}")
                
        logger.info("Exited monitor mode.")

    # -----------------------------------------------------------------------
    # Private thread workers (extracted from nested defs)
    # -----------------------------------------------------------------------

    def _input_worker_thread(self, start_event: threading.Event, exit_event: threading.Event) -> None:
        """
        Long-running daemon thread: reads stdin and sets *start_event*
        when the user types 'start', or *exit_event* for 'exit'.
        """
        while True:
            try:
                cmd = sys.stdin.readline()
                if not cmd:
                    continue
                cmd_stripped = cmd.strip().lower()
                if cmd_stripped == "start":
                    start_event.set()
                elif cmd_stripped == "exit":
                    exit_event.set()
                    break
            except Exception:
                pass

    def _has_main_wxapkg(self, folder: str) -> bool:
        """
        Return True if *folder* (relative to applet_dir) contains
        ``__APP__.wxapkg`` anywhere in its subtree.
        """
        folder_path = os.path.join(self.applet_dir, folder)
        for _root, _dirs, files in os.walk(folder_path):
            if "__APP__.wxapkg" in files:
                return True
        return False

    def _decompile_worker(self, folder: str, title: str) -> tuple:
        """
        ThreadPoolExecutor worker: decompile one mini program.

        Returns:
            (folder, title, ok: bool, out_dir: Optional[str])
        """
        ok, out_dir = self._decompile_and_local_scan(folder, title, log_verbose=False)
        return folder, title, ok, out_dir

    # -----------------------------------------------------------------------
    # Cache directory helpers
    # -----------------------------------------------------------------------

    def clean_wx_dirs(self) -> None:
        """Delete all 18-char wx* subdirectories from applet_dir."""
        try:
            with os.scandir(self.applet_dir) as entries:
                for entry in entries:
                    if (
                        entry.is_dir()
                        and entry.name.startswith("wx")
                        and len(entry.name) == 18
                    ):
                        shutil.rmtree(entry.path)
        except Exception as e:
            logger.error(str(e))

    def _detect_new_cache_dirs(self, before: set, timeout: float = 0.2) -> list:
        """
        Scan applet_dir once (after sleeping *timeout* seconds) and return
        directories that are not yet in *before*.

        The caller is responsible for adding returned folders to *before*
        only after confirming ``__APP__.wxapkg`` is present, so that
        partially-downloaded packages are retried on the next poll cycle.

        Args:
            before:  Set of already-known folder names (mutated in-place by caller).
            timeout: Polling interval in seconds.

        Returns:
            List of new folder names (may be empty).
        """
        try:
            sleep(timeout)
            current = {
                entry.name
                for entry in os.scandir(self.applet_dir)
                if entry.is_dir()
            }
            return list(current - before)
        except Exception as e:
            logger.error(f"WxTools._detect_new_cache_dirs error: {e}")
            return []

    def find_wxapkg(self, path: str) -> str:
        """
        Walk down into *path* until a leaf directory (no subdirs) is found
        and return it.  That leaf is the directory containing the raw .wxapkg.
        """
        current = path
        while True:
            entries = os.listdir(current)
            dirs = [e for e in entries if os.path.isdir(os.path.join(current, e))]
            if not dirs:
                return current
            current = os.path.join(current, dirs[0])

    def run_unpack(self, command: str, output_dir: str, max_retries: int = 5) -> bool:
        """
        Run the KillWxapkg unpack tool with retry logic.

        Returns:
            True  → unpacking ultimately failed (caller should abort).
            False → unpacking succeeded.
        """
        retry = 0
        success = False
        while retry < max_retries and not success:
            try:
                subprocess.run(
                    command,
                    shell=True,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=Config().wx_cmd_timeout,
                )
                file_count = sum(len(files) for _, _, files in os.walk(output_dir))
                if file_count > 2:
                    success = True
                else:
                    logger.error("Decompiled result directory is empty, retrying...")
                    retry += 1
            except subprocess.TimeoutExpired:
                logger.error("Unpack tool timed out, stopping this attempt")
                success = True  # treat timeout as "done enough"
            except subprocess.CalledProcessError:
                logger.error("Unpack command failed, retrying...")
                retry += 1

        if not success:
            logger.error("Reached maximum retry count, giving up on this mini program")
            return True  # signal failure
        return False

    # -----------------------------------------------------------------------
    # Mini program title helper
    # -----------------------------------------------------------------------

    def _safe_mini_title(self) -> str:
        """
        Retrieve the current mini program window title via WxHook.
        Falls back to ``HintWnd-<random>`` if the title cannot be determined.
        """
        try:
            wx_info = WxHook().get_wechat_info()
            title, _pid, _proc = wx_info[0]
        except Exception:
            title = "HintWnd"

        if title == "HintWnd":
            logger.info(
                "Detected HintWnd window title, "
                "failed to capture mini program name, using random suffix instead"
            )
            title = (
                "HintWnd-"
                + "".join(
                    random.choice(string.ascii_letters + string.digits)
                    for _ in range(8)
                )
            )
        return title

    # -----------------------------------------------------------------------
    # Core decompile + local scan
    # -----------------------------------------------------------------------

    def _decompile_and_local_scan(
        self, folder: str, title: str, log_verbose: bool = True
    ) -> tuple:
        """
        Decompile one mini program cache folder and run local analysis.

        Args:
            folder:      Cache folder name (relative to applet_dir).
            title:       Human-readable mini program name.
            log_verbose: Whether to emit INFO-level progress logs.

        Returns:
            (success: bool, output_dir: Optional[str])
        """
        try:
            result_dir = ensure_dir_exists(Config().output_dir)
            output_dir = os.path.join(result_dir, title)
            wxapkg_path = self.find_wxapkg(os.path.join(self.applet_dir, folder))

            if os.path.isdir(output_dir):
                if log_verbose:
                    logger.info(f"Mini program \"{title}\" already exists, skipping decompile")
                return True, output_dir

            if log_verbose:
                logger.info(
                    f"Detected new mini program window \"{title}\", starting decompile"
                )

            os.mkdir(output_dir)
            cmd = (
                f"{self.unpack_tool} "
                f'-id="{folder}" '
                f'-in="{wxapkg_path}" '
                f'-restore -pretty '
                f'-out "{output_dir}"'
            )
            unpack_failed = self.run_unpack(cmd, output_dir)

            if unpack_failed:
                file_count = sum(len(files) for _, _, files in os.walk(wxapkg_path))
                if file_count <= 1:
                    logger.error(
                        "No wxapkg encrypted file generated, very likely a network issue"
                    )
                else:
                    logger.error(
                        "wxapkg encrypted file exists but decompile failed, "
                        "please open an issue with details"
                    )
                os.rmdir(output_dir)
                self.clean_wx_dirs()
                return False, None

            if log_verbose:
                logger.info(f"Decompile finished, source output directory: {output_dir}")

            # Local analysis (URL + secret extraction)
            try:
                FileProcessor().process_directory(output_dir, output_dir, title)
                return True, output_dir
            except Exception as e:
                logger.error(f"Local scan failed for \"{title}\": {e}")
                return False, output_dir

        except Exception as e:
            logger.error(f"WxTools._decompile_and_local_scan error: {e}")
            return False, None
