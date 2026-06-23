# -*- coding: utf-8 -*-
"""
Configuration loader and logging setup for MiniScan.

All other modules should import `Config` from here rather than
reading config files directly.
"""
import os
import logging

from yaml import safe_load
from miniscan.utils.path_utils import get_config_path, get_base_dir, ensure_dir_exists


def setup_logging() -> None:
    """Configure application-wide logging.

    Output goes to two sinks simultaneously:
      - Console (stdout) — so operators see live progress.
      - Output/Log/scan_results.log — persistent record for later review.
    """
    config = Config()
    log_dir = ensure_dir_exists(config.log_dir)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(
                os.path.join(log_dir, "scan_results.log"), encoding="utf-8"
            ),
            logging.StreamHandler(),   # ← print to console as well
        ],
    )



class Config:
    """Holds all runtime settings loaded from config/config.yaml and config/rule.yaml."""

    def __init__(self) -> None:
        config_path = get_config_path("config.yaml")
        try:
            config = safe_load(open(config_path, "r", encoding="gb18030").read())
        except Exception:
            config = safe_load(open(config_path, "r", encoding="utf-8").read())

        mini_scan_cfg = config.get("mini_scan", {})

        self.wx_dir: str = mini_scan_cfg.get("wx_dir", "")

        # Output directory for decompiled mini program sources
        output_dir_config: str = mini_scan_cfg.get("output_dir", "./Output/Source")
        if os.path.isabs(output_dir_config):
            self.output_dir = output_dir_config
        else:
            self.output_dir = os.path.join(get_base_dir(), output_dir_config)

        # Logging directory
        self.log_dir = os.path.join(get_base_dir(), "Output", "Log")

        # Fortify config integration
        fortify_cfg = config.get("fortify_scan", {})
        self.fortify_enabled: bool = fortify_cfg.get("enabled", True)
        self.fortify_path: str = fortify_cfg.get("fortify_path", "")
        self.report_generator_path: str = fortify_cfg.get("report_generator_path", "")
        audit_dir_config: str = fortify_cfg.get("output_dir", "./Output/Audit")
        if os.path.isabs(audit_dir_config):
            self.audit_dir = audit_dir_config
        else:
            self.audit_dir = os.path.join(get_base_dir(), audit_dir_config)
        self.fortify_max_workers: int = fortify_cfg.get("max_workers", 1)

        self.asyncio_http_enabled: bool = mini_scan_cfg.get("asyncio_http_enabled", False)
        self.process_file: str = mini_scan_cfg.get("process_file", "Key.xlsx")
        self.wx_cmd_timeout: int = mini_scan_cfg.get("wx_cmd_timeout", 100)
        self.not_asyncio_http: list = mini_scan_cfg.get("not_asyncio_http", [])
        self.not_asyncio_status: list = mini_scan_cfg.get("not_asyncio_status", [])
        self.max_workers: int = mini_scan_cfg.get("max_workers", 5)

        self.req_headers: dict = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/58.0.3029.110 Safari/537.3"
            ),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.8",
        }

        # Regex rules from rule.yaml
        rule_path = get_config_path("rule.yaml")
        try:
            rule_config = safe_load(open(rule_path, "r", encoding="utf-8").read())
            rules = rule_config.get("rules", [])
            self._regex_patterns: dict = {
                rule["id"]: rule["pattern"]
                for rule in rules
                if rule.get("enabled", False) and rule.get("pattern", "")
            }
        except Exception as e:
            logging.warning("Failed to load rule.yaml, no regex rules will be applied: %s", e)
            self._regex_patterns = {}

        # URL extraction pattern (used by FileProcessor)
        self.url_pattern_raw: str = r"""
          (?:"|')
          (
            ((?:[a-zA-Z]{1,10}://|//)
            [^"'/]{1,}\.
            [a-zA-Z]{2,}[^"']{0,})
            |
            ((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]]
            [^"'><,;|()]{1,})
            |
            ([a-zA-Z0-9_\-/]{1,}/
            [a-zA-Z0-9_\-/]{1,}
            \.(?:[a-zA-Z]{1,4}|action)
            (?:[\?|/][^"|']{0,}|))
            |
            ([a-zA-Z0-9_\-]{1,}
            \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)
            (?:\?[^"|']{0,}|))
          )
          (?:"|')
        """
