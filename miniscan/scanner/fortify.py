# -*- coding: utf-8 -*-
"""
Fortify SAST scanner integration.

Moved from the top-level fortify_scan.py.  Logging is configured by the
application entry point (main.py) before this module is imported, so there
is no logging.basicConfig call here.
"""
import logging
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from miniscan.config import Config
from miniscan.utils.path_utils import ensure_dir_exists

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

# Configuration is now handled centrally by miniscan.config.Config


# ---------------------------------------------------------------------------
# FortifyScanner
# ---------------------------------------------------------------------------

class FortifyScanner:
    """Orchestrates Fortify SAST translation, scanning, and PDF report generation."""

    def __init__(
        self,
        fortify_path: str,
        result_dir: str,
        output_dir: str,
        report_generator_path: str,
        max_workers: int = 1,
    ) -> None:
        self.fortify_path = Path(fortify_path)
        self.result_dir = Path(result_dir)
        self.output_dir = Path(output_dir)
        self.report_generator_path = Path(report_generator_path)
        self.max_workers = max_workers

        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.sourceanalyzer = self.fortify_path / "bin" / "sourceanalyzer.exe"
        self.fortifyclient = self.fortify_path / "bin" / "fortifyclient.exe"
        self.rules_dir = self.fortify_path / "Core" / "config" / "rules"

        self.miniprogram_extensions = {
            ".js", ".wxml", ".wxss", ".json", ".jsx",
            ".ts", ".tsx", ".vue", ".html", ".css",
        }
        self.exclude_dirs = {
            "node_modules", ".git", "dist", "build",
            "test", "tests", "__tests__", "coverage",
        }
        self.exclude_files = {"*.min.js", "*.bundle.js", "*.map", "package-lock.json", "yarn.lock"}
        self.javascript_rules = [
            "core_javascript.bin",
            "extended_javascript.bin",
            "comm_universal.bin",
            "core_cloud.bin",
        ]

    # ------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------

    def validate_environment(self) -> None:
        """Raise FileNotFoundError if any required Fortify path is missing."""
        if not self.fortify_path.exists():
            raise FileNotFoundError(f"Fortify path does not exist: {self.fortify_path}")
        if not self.sourceanalyzer.exists():
            raise FileNotFoundError(f"sourceanalyzer.exe not found: {self.sourceanalyzer}")
        if not self.report_generator_path.exists():
            raise FileNotFoundError(
                f"ReportGenerator.bat not found: {self.report_generator_path}"
            )
        if not self.result_dir.exists():
            raise FileNotFoundError(f"Source directory does not exist: {self.result_dir}")

        missing_rules = [
            r for r in self.javascript_rules if not (self.rules_dir / r).exists()
        ]
        if missing_rules:
            logger.warning(f"The following rule files do not exist: {missing_rules}")

        logger.info("Fortify environment validation passed")

    # ------------------------------------------------------------------
    # Project discovery
    # ------------------------------------------------------------------

    def get_miniprogram_projects(self) -> list:
        """Return all mini program project directories under result_dir."""
        projects = []
        for item in self.result_dir.iterdir():
            if item.is_dir():
                projects.append(item)
                logger.info(f"Detected mini program project: {item.name}")
        logger.info(f"Total mini program projects found: {len(projects)}")
        return projects

    def is_relevant_file(self, file_path: Path) -> bool:
        """Return True if the file should be included in the Fortify scan."""
        if file_path.suffix.lower() in self.miniprogram_extensions:
            return not any(pat in str(file_path) for pat in self.exclude_files)
        return False

    def get_source_files(self, project_dir: Path) -> list:
        """Collect all scannable source files within a project directory."""
        source_files = []
        total = 0
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for file in files:
                total += 1
                fp = Path(root) / file
                if self.is_relevant_file(fp):
                    source_files.append(str(fp))
        logger.info(
            f"Project {project_dir.name}: total files {total}, "
            f"files to scan {len(source_files)}"
        )
        return source_files

    def build_rules_argument(self) -> Optional[str]:
        """Build the semicolon-joined rule file argument for sourceanalyzer."""
        rule_paths = [
            str(self.rules_dir / r)
            for r in self.javascript_rules
            if (self.rules_dir / r).exists()
        ]
        if not rule_paths:
            logger.warning("No JavaScript rule files found, using Fortify default rules")
            return None
        rules_arg = ";".join(rule_paths)
        logger.info(f"Using rule files: {rules_arg}")
        return rules_arg

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def translate_project(self, project_dir: Path, project_id: str, orig_name: str) -> bool:
        """Translate project source files into a Fortify scan session."""
        try:
            if not self.get_source_files(project_dir):
                logger.warning(f"Project {orig_name} has no relevant source files to scan")
                return False

            clean_cmd = [str(self.sourceanalyzer), "-b", project_id, "-clean"]
            logger.info(
                f"Cleaning previous Fortify session for project {orig_name} "
                f"(ID: {project_id}): {' '.join(clean_cmd)}"
            )
            subprocess.run(clean_cmd, check=True, capture_output=False, text=True, timeout=300)

            translate_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-logfile", str(self.output_dir / f"{orig_name}_translate.log"),
                str(project_dir),
            ]
            for d in self.exclude_dirs:
                translate_cmd.extend(["-exclude", f"{project_dir.name}/{d}"])
            for pat in self.exclude_files:
                translate_cmd.extend(["-exclude", f"**/{pat}"])

            logger.info(f"Start translating project: {orig_name} (ID: {project_id})")
            start = time.time()
            subprocess.run(
                translate_cmd, check=True, capture_output=False, text=True, timeout=1800
            )
            logger.info(
                f"Translation completed: {orig_name}, "
                f"duration: {time.time() - start:.2f} seconds"
            )
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Translation error - {orig_name} (ID: {project_id}): {e}")
        except subprocess.TimeoutExpired:
            logger.error(f"Translation timeout - {orig_name} (ID: {project_id})")
        except Exception as e:
            logger.error(f"Unexpected translation exception - {orig_name} (ID: {project_id}): {e}")
        return False

    def generate_pdf_report(self, fpr_id_file: Path, project_id: str, orig_name: str) -> Optional[str]:
        """Generate a PDF report from an FPR file via Fortify ReportGenerator."""
        try:
            pdf_id_file = self.output_dir / f"{project_id}.pdf"
            report_cmd = [
                str(self.report_generator_path),
                "-source", str(fpr_id_file),
                "-format", "pdf",
                "-f", str(pdf_id_file),
            ]
            logger.info(f"Generating PDF report for project: {orig_name} (ID: {project_id})")
            subprocess.run(
                report_cmd, check=True, capture_output=False, text=True, timeout=600
            )

            if pdf_id_file.exists():
                pdf_orig_file = self.output_dir / f"{orig_name}.pdf"
                os.rename(pdf_id_file, pdf_orig_file)
                logger.info(f"Renamed PDF file: {project_id}.pdf -> {orig_name}.pdf")
                size_mb = pdf_orig_file.stat().st_size / (1024 * 1024)
                logger.info(
                    f"PDF report generated: {orig_name}, "
                    f"file: {pdf_orig_file} ({size_mb:.2f} MB)"
                )
                return str(pdf_orig_file)
            else:
                logger.error(f"PDF report generation failed: {orig_name}, no PDF file generated")

        except subprocess.CalledProcessError as e:
            logger.error(f"PDF report error - {orig_name} (ID: {project_id}): {e}")
        except subprocess.TimeoutExpired:
            logger.error(f"PDF report timeout - {orig_name} (ID: {project_id})")
        except Exception as e:
            logger.error(f"Unexpected PDF report exception - {orig_name} (ID: {project_id}): {e}")
        return None

    def run_scan(self, project_dir: Path, project_id: str, orig_name: str):
        """Run the full Fortify scan pipeline for a single project."""
        logger.info(f"Starting scan for project: {orig_name} (ID: {project_id})")
        try:
            if not self.translate_project(project_dir, project_id, orig_name):
                logger.error(f"Project {orig_name} translation failed, skipping scan")
                return None, None

            rules_arg = self.build_rules_argument()
            fpr_id_file = self.output_dir / f"{project_id}.fpr"
            scan_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-scan",
                "-f", str(fpr_id_file),
                "-format", "fpr",
                "-mt",
                "-Dcom.fortify.sca.Xmx=2G",
                "-Dcom.fortify.sca.ThreadCount=2",
                "-Dcom.fortify.sca.limiters=600",
            ]
            if rules_arg:
                scan_cmd.extend(["-rules", rules_arg])

            logger.info(f"Executing scan command for project: {orig_name} (ID: {project_id})")
            logger.info(f"Scan command: {' '.join(scan_cmd)}")

            start = time.time()
            subprocess.run(
                scan_cmd, check=True, capture_output=False, text=True, timeout=3600
            )
            logger.info(
                f"Scan completed: {orig_name}, "
                f"duration: {time.time() - start:.2f} seconds"
            )

            if fpr_id_file.exists():
                pdf_file = self.generate_pdf_report(fpr_id_file, project_id, orig_name)
                fpr_orig_file = self.output_dir / f"{orig_name}.fpr"
                os.rename(fpr_id_file, fpr_orig_file)
                logger.info(f"Renamed FPR file: {project_id}.fpr -> {orig_name}.fpr")
                return str(fpr_orig_file), pdf_file
            else:
                logger.error(f"Scan failed: {orig_name}, no FPR result file generated")

        except subprocess.CalledProcessError as e:
            logger.error(f"Scan error - {orig_name} (ID: {project_id}): {e}")
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout - {orig_name} (ID: {project_id})")
        except Exception as e:
            logger.error(f"Unexpected scan exception - {orig_name} (ID: {project_id}): {e}")
        return None, None

    def generate_summary_report(self, scan_results: list) -> None:
        """Write a plain-text summary of all scan outcomes to Output/Log."""
        config = Config()
        log_dir = ensure_dir_exists(config.log_dir)
        summary_file = Path(log_dir) / "min_code_scan_summary.txt"

        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("MiniScan Fortify Scan Summary Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Scan time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total projects: {len(scan_results)}\n")

            successful = [r for r in scan_results if r["success"]]
            failed = [r for r in scan_results if not r["success"]]
            f.write(f"Successful scans: {len(successful)}\n")
            f.write(f"Failed scans: {len(failed)}\n")
            f.write(f"Rule sets used: {', '.join(self.javascript_rules)}\n\n")

            f.write("Successful projects:\n")
            for r in successful:
                f.write(
                    f"  - {r['project_name']}: "
                    f"FPR={r['fpr_file']}, PDF={r.get('pdf_file', 'N/A')}\n"
                )
            if failed:
                f.write("\nFailed projects:\n")
                for r in failed:
                    f.write(f"  - {r['project_name']}: {r.get('error', 'Unknown error')}\n")

        logger.info(f"Summary report generated: {summary_file}")

    def run_all_scans(self) -> None:
        """Run Fortify scans for all mini program projects under Output/Source."""
        logger.info("Starting batch Fortify scan for all mini program projects")
        self.validate_environment()

        all_projects = self.get_miniprogram_projects()
        if not all_projects:
            logger.warning("No mini program projects found")
            return

        # Skip already-scanned projects
        projects = [
            p for p in all_projects
            if not (self.output_dir / f"{p.name}.fpr").exists()
            and not (self.output_dir / f"{p.name}.pdf").exists()
        ]
        if not projects:
            logger.info("All projects already scanned, nothing to do")
            return

        logger.info(f"Projects to scan: {len(projects)}")
        project_to_id = {p.name: f"{i:03d}" for i, p in enumerate(projects)}
        logger.info(f"Project ID mapping: {project_to_id}")

        scan_results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_name = {
                executor.submit(self.run_scan, p, project_to_id[p.name], p.name): p.name
                for p in projects
            }
            for future in as_completed(future_to_name):
                orig_name = future_to_name[future]
                try:
                    fpr_file, pdf_file = future.result()
                    if fpr_file:
                        scan_results.append(
                            {"project_name": orig_name, "fpr_file": fpr_file,
                             "pdf_file": pdf_file, "success": True}
                        )
                        logger.info(f"Project {orig_name} scanned successfully")
                    else:
                        scan_results.append(
                            {"project_name": orig_name,
                             "error": "Scan failed, no result file generated", "success": False}
                        )
                        logger.error(f"Project {orig_name} scan failed")
                except Exception as e:
                    scan_results.append(
                        {"project_name": orig_name, "error": str(e), "success": False}
                    )
                    logger.error(f"Project {orig_name} execution exception: {e}")

        self.generate_summary_report(scan_results)
        logger.info("All Fortify scan tasks completed")


# ---------------------------------------------------------------------------
# Entry point (used by monitor_mode_monitor and --scan-all)
# ---------------------------------------------------------------------------

def main() -> int:
    """Run all Fortify scans based on configuration. Returns exit code."""
    config = Config()
    if not config.fortify_enabled:
        logger.info("Fortify scan is disabled in config.")
        return 0

    try:
        scanner = FortifyScanner(
            fortify_path=config.fortify_path,
            result_dir=config.output_dir,
            output_dir=config.audit_dir,
            report_generator_path=config.report_generator_path,
            max_workers=config.fortify_max_workers,
        )
        scanner.run_all_scans()
    except Exception as e:
        logger.error(f"Fatal error during Fortify scan: {e}")
        return 1
    return 0


if __name__ == "__main__":
    exit(main())
