# -*- coding: utf-8 -*-
import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from yaml import safe_load
from path_utils import get_base_dir, get_config_path, ensure_dir_exists

BASE_DIR = get_base_dir()
CONFIG_DIR = os.path.join(BASE_DIR, "config")
OUTPUT_DIR = os.path.join(BASE_DIR, "Output")
SOURCE_DIR = os.path.join(OUTPUT_DIR, "Source")
AUDIT_DIR = os.path.join(OUTPUT_DIR, "Audit")
LOG_DIR = os.path.join(OUTPUT_DIR, "Log")

ensure_dir_exists(SOURCE_DIR)
ensure_dir_exists(AUDIT_DIR)
ensure_dir_exists(LOG_DIR)

# Configure logging for Fortify scanner
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'fortify_fortify.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def load_fortify_config():
    """Load Fortify scanning configuration from config/config.yaml."""
    config_path = get_config_path("config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = safe_load(f) or {}
    fortify_cfg = cfg.get("fortify_scan", {})
    miniscan_cfg = cfg.get("mini_scan", {})
    return {
        "enabled": fortify_cfg.get("enabled", True),
        "fortify_path": fortify_cfg.get("fortify_path", r"C:\Program Files\Fortify\OpenText_SAST_Fortify_25.3.0"),
        "report_generator_path": fortify_cfg.get("report_generator_path", r"C:\Program Files\Fortify\OpenText_Application_Security_Tools_25.2.0\bin\ReportGenerator.bat"),
        "result_dir": miniscan_cfg.get("output_dir", os.path.join(BASE_DIR, "Output", "Source")),
        "output_dir": fortify_cfg.get("output_dir", os.path.join(BASE_DIR, "Output", "Audit")),
        "max_workers": fortify_cfg.get("max_workers", 1),
    }
class FortifyScanner:
    def __init__(self, fortify_path, result_dir, output_dir, report_generator_path, max_workers=1):
        """
        Initialize Fortify scanner.
       
        Args:
            fortify_path: Fortify installation path
            result_dir: Mini program source root directory
            output_dir: Fortify scan result output directory
            report_generator_path: ReportGenerator.bat path
            max_workers: maximum number of concurrent scan workers
        """
        self.fortify_path = Path(fortify_path)
        self.result_dir = Path(result_dir)
        self.output_dir = Path(output_dir)
        self.report_generator_path = Path(report_generator_path)
        self.max_workers = max_workers
       
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
       
        # Fortify CLI paths
        self.sourceanalyzer = self.fortify_path / "bin" / "sourceanalyzer.exe"
        self.fortifyclient = self.fortify_path / "bin" / "fortifyclient.exe"
       
        # Rules directory
        self.rules_dir = self.fortify_path / "Core" / "config" / "rules"
       
        # Mini program related file extensions
        self.miniprogram_extensions = {
            '.js', '.wxml', '.wxss', '.json', '.jsx', '.ts', '.tsx', '.vue', '.html', '.css'
        }
       
        # Directories and files to exclude from scanning
        self.exclude_dirs = {
            'node_modules', '.git', 'dist', 'build',
            'test', 'tests', '__tests__', 'coverage'
        }
        self.exclude_files = {
            '*.min.js', '*.bundle.js', '*.map',
            'package-lock.json', 'yarn.lock'
        }
       
        # JavaScript and frontend related rule files
        self.javascript_rules = [
            "core_javascript.bin",
            "extended_javascript.bin",
            "comm_universal.bin",  # Common rules
            "core_cloud.bin"       # Cloud security rules
        ]
    def validate_environment(self):
        """Validate environment and required paths."""
        if not self.fortify_path.exists():
            raise FileNotFoundError(f"Fortify path does not exist: {self.fortify_path}")
       
        if not self.sourceanalyzer.exists():
            raise FileNotFoundError(f"sourceanalyzer.exe not found: {self.sourceanalyzer}")
       
        if not self.report_generator_path.exists():
            raise FileNotFoundError(f"ReportGenerator.bat not found: {self.report_generator_path}")
       
        if not self.result_dir.exists():
            raise FileNotFoundError(f"Source directory does not exist: {self.result_dir}")
       
        # Validate that rule files exist
        missing_rules = []
        for rule in self.javascript_rules:
            rule_path = self.rules_dir / rule
            if not rule_path.exists():
                missing_rules.append(rule)
       
        if missing_rules:
            logger.warning(f"The following rule files do not exist: {missing_rules}")
       
        logger.info("Fortify environment validation passed")
    def get_miniprogram_projects(self):
        """Get all mini program project directories under result_dir."""
        projects = []
        for item in self.result_dir.iterdir():
            if item.is_dir():
                projects.append(item)
                logger.info(f"Detected mini program project: {item.name}")
       
        logger.info(f"Total mini program projects found: {len(projects)}")
        return projects
    def is_relevant_file(self, file_path):
        """Check whether a file is relevant for scanning."""
        if file_path.suffix.lower() in self.miniprogram_extensions:
            # Check against exclude patterns
            for pattern in self.exclude_files:
                if pattern in str(file_path):
                    return False
            return True
        return False
    def get_source_files(self, project_dir):
        """Collect all relevant source files within a project directory."""
        source_files = []
        total_files = 0
       
        for root, dirs, files in os.walk(project_dir):
            # Remove excluded directories from traversal
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
           
            for file in files:
                total_files += 1
                file_path = Path(root) / file
                if self.is_relevant_file(file_path):
                    source_files.append(str(file_path))
       
        logger.info(
            f"Project {project_dir.name}: total files {total_files}, files to scan {len(source_files)}"
        )
        return source_files
    def build_rules_argument(self):
        """Build the rule file argument for sourceanalyzer."""
        rule_paths = []
        for rule_file in self.javascript_rules:
            rule_path = self.rules_dir / rule_file
            if rule_path.exists():
                rule_paths.append(str(rule_path))
       
        if not rule_paths:
            logger.warning("No JavaScript rule files found, using Fortify default rules")
            return None
       
        # Join rule paths with semicolons
        rules_arg = ";".join(rule_paths)
        logger.info(f"Using rule files: {rules_arg}")
        return rules_arg
    def translate_project(self, project_dir, project_id, orig_name):
        """Translate project source files into a Fortify scan session."""
        try:
            # Get candidate source files (for logging only)
            source_files = self.get_source_files(project_dir)
            if not source_files:
                logger.warning(f"Project {orig_name} has no relevant source files to scan")
                return False
           
            # Clean any previous translation for this project id
            clean_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-clean"
            ]
           
            logger.info(f"Cleaning previous Fortify session for project {orig_name} (ID: {project_id}): {' '.join(clean_cmd)}")
            result_clean = subprocess.run(clean_cmd, check=True, capture_output=False, text=True, timeout=300)
           
            # Build translation command
            translate_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-logfile", str(self.output_dir / f"{orig_name}_translate.log"),
                str(project_dir)
            ]
           
            # Add excluded directories
            for dir_pattern in self.exclude_dirs:
                translate_cmd.extend(["-exclude", f"{project_dir.name}/{dir_pattern}"])
           
            # Add excluded file patterns (with wildcards)
            for file_pattern in self.exclude_files:
                translate_cmd.extend(["-exclude", f"**/{file_pattern}"])
           
            logger.info(f"Start translating project: {orig_name} (ID: {project_id})")
            logger.debug(f"Translate command: {' '.join(translate_cmd)}")
           
            # Execute translation
            start_time = time.time()
            result = subprocess.run(
                translate_cmd,
                check=True,
                capture_output=False,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            end_time = time.time()
           
            translate_duration = end_time - start_time
            logger.info(f"Translation completed: {orig_name}, duration: {translate_duration:.2f} seconds")
           
            return True
           
        except subprocess.CalledProcessError as e:
            logger.error(f"Translation error - {orig_name} (ID: {project_id}): {e}")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"Translation timeout - {orig_name} (ID: {project_id})")
            return False
        except Exception as e:
            logger.error(f"Unexpected translation exception - {orig_name} (ID: {project_id}): {e}")
            return False
    def generate_pdf_report(self, fpr_id_file, project_id, orig_name):
        """Generate PDF report via Fortify ReportGenerator."""
        try:
            pdf_id_file = self.output_dir / f"{project_id}.pdf"
            report_cmd = [
                str(self.report_generator_path),
                "-source", str(fpr_id_file),
                "-format", "pdf",
                "-f", str(pdf_id_file)
            ]
           
            logger.info(f"Generating PDF report for project: {orig_name} (ID: {project_id})")
            logger.debug(f"Report command: {' '.join(report_cmd)}")
           
            result = subprocess.run(
                report_cmd,
                check=True,
                capture_output=False,
                text=True,
                timeout=600  # 10 minutes timeout
            )
           
            if pdf_id_file.exists():
                # Rename PDF back to original project name
                pdf_orig_file = self.output_dir / f"{orig_name}.pdf"
                os.rename(pdf_id_file, pdf_orig_file)
                logger.info(f"Renamed PDF file: {project_id}.pdf -> {orig_name}.pdf")
               
                file_size = pdf_orig_file.stat().st_size / (1024 * 1024)  # MB
                logger.info(f"PDF report generated successfully: {orig_name}, file: {pdf_orig_file} ({file_size:.2f} MB)")
                return str(pdf_orig_file)
            else:
                logger.error(f"PDF report generation failed: {orig_name}, no PDF file generated")
                return None
               
        except subprocess.CalledProcessError as e:
            logger.error(f"PDF report generation error - {orig_name} (ID: {project_id}): {e}")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"PDF report generation timeout - {orig_name} (ID: {project_id})")
            return None
        except Exception as e:
            logger.error(f"Unexpected PDF report generation exception - {orig_name} (ID: {project_id}): {e}")
            return None
    def run_scan(self, project_dir, project_id, orig_name):
        """Run Fortify scan for a single project."""
        logger.info(f"Starting scan for project: {orig_name} (ID: {project_id})")
       
        try:
            # First translate the project into a Fortify session
            if not self.translate_project(project_dir, project_id, orig_name):
                logger.error(f"Project {orig_name} translation failed, skipping scan")
                return None, None
           
            # Build rules argument
            rules_arg = self.build_rules_argument()
           
            # Run the scan
            fpr_id_file = self.output_dir / f"{project_id}.fpr"
            scan_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-scan",
                "-f", str(fpr_id_file),
                "-format", "fpr",
                "-mt",  # enable multithreaded scanning
                # "-Dcom.fortify.sca.ProjectRoot=.",  # set project root if needed
                "-Dcom.fortify.sca.Xmx=2G",          # limit memory usage
                "-Dcom.fortify.sca.ThreadCount=2",   # limit scan threads
                "-Dcom.fortify.sca.limiters=600"     # scan time limit
            ]
           
            # Add rule file argument
            if rules_arg:
                scan_cmd.extend(["-rules", rules_arg])
           
            logger.info(f"Executing scan command for project: {orig_name} (ID: {project_id})")
            logger.info(f"Scan command: {' '.join(scan_cmd)}")
           
            # Execute scan
            start_time = time.time()
            result = subprocess.run(
                scan_cmd,
                check=True,
                capture_output=False,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            end_time = time.time()
           
            scan_duration = end_time - start_time
            logger.info(f"Scan completed: {orig_name}, duration: {scan_duration:.2f} seconds")
           
            if fpr_id_file.exists():
                # Generate PDF report from ID-based FPR file
                pdf_file = self.generate_pdf_report(fpr_id_file, project_id, orig_name)
               
                # Rename FPR file back to original project name
                fpr_orig_file = self.output_dir / f"{orig_name}.fpr"
                os.rename(fpr_id_file, fpr_orig_file)
                logger.info(f"Renamed FPR file: {project_id}.fpr -> {orig_name}.fpr")
               
                return str(fpr_orig_file), pdf_file
            else:
                logger.error(f"Scan failed: {orig_name}, no FPR result file generated")
                return None, None
               
        except subprocess.CalledProcessError as e:
            logger.error(f"Scan error - {orig_name} (ID: {project_id}): {e}")
            return None, None
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout - {orig_name} (ID: {project_id})")
            return None, None
        except Exception as e:
            logger.error(f"Unexpected scan exception - {orig_name} (ID: {project_id}): {e}")
            return None, None
    def generate_summary_report(self, scan_results):
        """Generate a summary text report for all scans."""
        summary_file = Path(LOG_DIR) / "min_code_scan_summary.txt"
       
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("MiniScan Fortify Scan Summary Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Scan time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total projects: {len(scan_results)}\n")
           
            successful_scans = [r for r in scan_results if r['success']]
            failed_scans = [r for r in scan_results if not r['success']]
           
            f.write(f"Successful scans: {len(successful_scans)}\n")
            f.write(f"Failed scans: {len(failed_scans)}\n")
            f.write(f"Rule sets used: {', '.join(self.javascript_rules)}\n\n")
           
            f.write("Successful projects:\n")
            for result in successful_scans:
                f.write(f" - {result['project_name']}: FPR={result['fpr_file']}, PDF={result.get('pdf_file', 'N/A')}\n")
           
            if failed_scans:
                f.write("\nFailed projects:\n")
                for result in failed_scans:
                    f.write(f" - {result['project_name']}: {result.get('error', 'Unknown error')}\n")
       
        logger.info(f"Summary report generated: {summary_file}")
    def run_all_scans(self):
        """Run Fortify scans for all mini program projects under Output/Source."""
        logger.info("Starting batch Fortify scan for all mini program projects")
       
        # Validate environment
        self.validate_environment()
        # Get all projects
        all_projects = self.get_miniprogram_projects()
        if not all_projects:
            logger.warning("No mini program projects found")
            return
       
        # Filter out projects that already have completed scan results
        projects = []
        for proj in all_projects:
            fpr_file = self.output_dir / f"{proj.name}.fpr"
            pdf_file = self.output_dir / f"{proj.name}.pdf"
            if fpr_file.exists() or pdf_file.exists():
                logger.info(f"Skipping already scanned project: {proj.name}")
            else:
                projects.append(proj)
       
        if not projects:
            logger.info("All projects already scanned, nothing to do")
            return
       
        logger.info(f"Projects to scan: {len(projects)}")
       
        # Create project ID mapping (decouple from project names)
        project_to_id = {proj.name: f"{i:03d}" for i, proj in enumerate(projects)}
        logger.info(f"Project ID mapping: {project_to_id}")
       
        scan_results = []
       
        # Use thread pool to execute scans
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            future_to_project = {
                executor.submit(self.run_scan, project, project_to_id[project.name], project.name): project.name
                for project in projects
            }
           
            # Collect results
            for future in as_completed(future_to_project):
                orig_name = future_to_project[future]
                project_id = project_to_id[orig_name]
                try:
                    fpr_file, pdf_file = future.result()
                    if fpr_file:
                        scan_results.append({
                            'project_name': orig_name,
                            'fpr_file': fpr_file,
                            'pdf_file': pdf_file,
                            'success': True
                        })
                        logger.info(f"Project {orig_name} scanned successfully")
                    else:
                        scan_results.append({
                            'project_name': orig_name,
                            'error': 'Scan failed, no result file generated',
                            'success': False
                        })
                        logger.error(f"Project {orig_name} scan failed")
                except Exception as e:
                    scan_results.append({
                        'project_name': orig_name,
                        'error': str(e),
                        'success': False
                    })
                    logger.error(f"Project {orig_name} execution exception: {e}")
       
        # Generate summary report
        self.generate_summary_report(scan_results)
        logger.info("All Fortify scan tasks completed")
def main():
    """Entry point to run all Fortify scans based on configuration."""
    cfg = load_fortify_config()

    try:
        # Create scanner instance
        scanner = FortifyScanner(
            fortify_path=cfg["fortify_path"],
            result_dir=cfg["result_dir"],
            output_dir=cfg["output_dir"],
            report_generator_path=cfg["report_generator_path"],
            max_workers=cfg["max_workers"],
        )

        # Run scans
        scanner.run_all_scans()

    except Exception as e:
        logger.error(f"Fatal error occurred during Fortify scan: {e}")
        return 1

    return 0
if __name__ == "__main__":
    exit(main())