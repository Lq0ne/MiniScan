# -*- coding: utf-8 -*-
"""
Frida-based hook for WeChat mini program DevTools.

Classes
-------
WxHook              – attach a Frida script to the WeChatAppEx.exe process.

Functions
---------
on_message_handler  – default Frida message callback that writes to the logger.
run_wechat_hook     – convenience wrapper used as a daemon thread target.
"""
import logging
import sys
from typing import Optional

import frida
import psutil
import win32gui
import win32process

from miniscan.utils.path_utils import get_tools_path

logger = logging.getLogger(__name__)


class WxHook:
    """Attach a Frida instrumentation script to the active WeChat mini program process."""

    def __init__(self, js_path: Optional[str] = None) -> None:
        if js_path is None:
            js_path = get_tools_path("WeChatAppEx.exe.js")
        self.hook_js: str = js_path
        self.session = None

    # ------------------------------------------------------------------
    # Process discovery
    # ------------------------------------------------------------------

    def get_wechat_info(self) -> list:
        """
        Enumerate all visible windows and return info for WeChatAppEx.exe windows.

        Returns:
            List of (window_title, pid, process_name) tuples.
        """
        try:
            info: list = []

            def _enum_callback(hwnd, _extra):
                text = win32gui.GetWindowText(hwnd)
                if text:
                    pid = win32process.GetWindowThreadProcessId(hwnd)
                    proc = psutil.Process(pid[1])
                    if proc.name() == "WeChatAppEx.exe" and text not in [
                        "微信", "MSCTFIME UI", "Default IME"
                    ]:
                        info.append((text, pid[1], proc.name()))

            win32gui.EnumWindows(_enum_callback, None)
            return info
        except Exception as e:
            logger.error(f"WxHook.get_wechat_info error: {e}")
            return []

    # ------------------------------------------------------------------
    # Hook lifecycle
    # ------------------------------------------------------------------

    def attach_hook(self, on_message_callback) -> None:
        """
        Attach the Frida script to the first detected WeChatAppEx.exe process.

        Blocks until stdin is closed or a KeyboardInterrupt is received.
        Detaches cleanly on exit.
        """
        info = self.get_wechat_info()
        if not info:
            logger.error("No WeChat mini program window detected")
            return

        title, pid, proc_name = info[0]
        logger.info(f"Window Title: {title}, PID: {pid}, Process Name: {proc_name}")
        try:
            self.session = frida.attach(pid)
            with open(self.hook_js, "r", encoding="utf-8") as f:
                script = self.session.create_script(f.read())

            script.on("message", on_message_callback)
            script.load()
            sys.stdin.read()
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received, detaching from process...")
        finally:
            if self.session is not None:
                self.session.detach()


# ---------------------------------------------------------------------------
# Default message handler
# ---------------------------------------------------------------------------

def on_message_handler(message: dict, data) -> None:
    """Default Frida message callback: log payloads at INFO level."""
    if message.get("type") == "send":
        logger.info(f"[*] {message['payload']}")
    else:
        logger.info(str(message))


# ---------------------------------------------------------------------------
# Convenience thread target
# ---------------------------------------------------------------------------

def run_wechat_hook() -> None:
    """Attach the default hook to the current WeChat mini program process."""
    WxHook().attach_hook(on_message_handler)
