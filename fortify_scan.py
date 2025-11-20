import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from yaml import safe_load

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
OUTPUT_DIR = os.path.join(BASE_DIR, "Output")
SOURCE_DIR = os.path.join(OUTPUT_DIR, "Source")
AUDIT_DIR = os.path.join(OUTPUT_DIR, "Audit")
LOG_DIR = os.path.join(OUTPUT_DIR, "Log")

os.makedirs(SOURCE_DIR, exist_ok=True)
os.makedirs(AUDIT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# 配置日志
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
    """从 config/config.yaml 加载 Fortify 扫描相关配置"""
    config_path = os.path.join(CONFIG_DIR, "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = safe_load(f) or {}
    fortify_cfg = cfg.get("fortify_scan", {})
    return {
        "enabled": fortify_cfg.get("enabled", True),
        "fortify_path": fortify_cfg.get("fortify_path", r"C:\Program Files\Fortify\OpenText_SAST_Fortify_25.3.0"),
        "report_generator_path": fortify_cfg.get("report_generator_path", r"C:\Program Files\Fortify\OpenText_Application_Security_Tools_25.2.0\bin\ReportGenerator.bat"),
        "result_dir": fortify_cfg.get("result_dir", "./Output/Source"),
        "output_dir": fortify_cfg.get("output_dir", "./Output/Audit"),
        "max_workers": fortify_cfg.get("max_workers", 1),
    }
class FortifyScanner:
    def __init__(self, fortify_path, result_dir, output_dir, report_generator_path, max_workers=1):
        """
        初始化Fortify扫描器
       
        Args:
            fortify_path: Fortify安装路径
            result_dir: 小程序源码目录
            output_dir: 扫描结果输出目录
            report_generator_path: ReportGenerator.bat路径
            max_workers: 最大线程数
        """
        self.fortify_path = Path(fortify_path)
        self.result_dir = Path(result_dir)
        self.output_dir = Path(output_dir)
        self.report_generator_path = Path(report_generator_path)
        self.max_workers = max_workers
       
        # 创建输出目录
        self.output_dir.mkdir(parents=True, exist_ok=True)
       
        # Fortify命令行工具路径
        self.sourceanalyzer = self.fortify_path / "bin" / "sourceanalyzer.exe"
        self.fortifyclient = self.fortify_path / "bin" / "fortifyclient.exe"
       
        # 规则文件路径
        self.rules_dir = self.fortify_path / "Core" / "config" / "rules"
       
        # 小程序相关文件扩展名
        self.miniprogram_extensions = {
            '.js', '.wxml', '.wxss', '.json', '.jsx', '.ts', '.tsx', '.vue', '.html', '.css'
        }
       
        # 需要排除的目录和文件
        self.exclude_dirs = {
            'node_modules', '.git', 'dist', 'build',
            'test', 'tests', '__tests__', 'coverage'
        }
        self.exclude_files = {
            '*.min.js', '*.bundle.js', '*.map',
            'package-lock.json', 'yarn.lock'
        }
       
        # JavaScript和前端相关规则文件
        self.javascript_rules = [
            "core_javascript.bin",
            "extended_javascript.bin",
            "comm_universal.bin", # 通用规则
            "core_cloud.bin" # 云安全相关规则
        ]
    def validate_environment(self):
        """验证环境和路径"""
        if not self.fortify_path.exists():
            raise FileNotFoundError(f"Fortify路径不存在: {self.fortify_path}")
       
        if not self.sourceanalyzer.exists():
            raise FileNotFoundError(f"sourceanalyzer.exe未找到: {self.sourceanalyzer}")
       
        if not self.report_generator_path.exists():
            raise FileNotFoundError(f"ReportGenerator.bat未找到: {self.report_generator_path}")
       
        if not self.result_dir.exists():
            raise FileNotFoundError(f"源码目录不存在: {self.result_dir}")
       
        # 验证规则文件是否存在
        missing_rules = []
        for rule in self.javascript_rules:
            rule_path = self.rules_dir / rule
            if not rule_path.exists():
                missing_rules.append(rule)
       
        if missing_rules:
            logger.warning(f"以下规则文件不存在: {missing_rules}")
       
        logger.info("环境验证通过")
    def get_miniprogram_projects(self):
        """获取所有小程序项目目录"""
        projects = []
        for item in self.result_dir.iterdir():
            if item.is_dir():
                projects.append(item)
                logger.info(f"发现小程序项目: {item.name}")
       
        logger.info(f"共找到 {len(projects)} 个小程序项目")
        return projects
    def is_relevant_file(self, file_path):
        """检查文件是否为需要扫描的相关文件"""
        if file_path.suffix.lower() in self.miniprogram_extensions:
            # 检查是否在排除模式中
            for pattern in self.exclude_files:
                if pattern in str(file_path):
                    return False
            return True
        return False
    def get_source_files(self, project_dir):
        """获取项目中需要扫描的源文件"""
        source_files = []
        total_files = 0
       
        for root, dirs, files in os.walk(project_dir):
            # 排除不需要的目录
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
           
            for file in files:
                total_files += 1
                file_path = Path(root) / file
                if self.is_relevant_file(file_path):
                    source_files.append(str(file_path))
       
        logger.info(f"项目 {project_dir.name}: 总文件数 {total_files}, 扫描文件数 {len(source_files)}")
        return source_files
    def build_rules_argument(self):
        """构建规则文件参数"""
        rule_paths = []
        for rule_file in self.javascript_rules:
            rule_path = self.rules_dir / rule_file
            if rule_path.exists():
                rule_paths.append(str(rule_path))
       
        if not rule_paths:
            logger.warning("未找到任何规则文件，将使用默认规则")
            return None
       
        # 将规则文件路径用分号连接
        rules_arg = ";".join(rule_paths)
        logger.info(f"使用规则文件: {rules_arg}")
        return rules_arg
    def translate_project(self, project_dir, project_id, orig_name):
        """翻译项目文件（构建扫描会话）"""
        try:
            # 获取源文件（仅用于日志计数）
            source_files = self.get_source_files(project_dir)
            if not source_files:
                logger.warning(f"项目 {orig_name} 没有找到需要扫描的源文件")
                return False
           
            # 清理之前的翻译
            clean_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-clean"
            ]
           
            logger.info(f"执行清理项目 {orig_name} (ID: {project_id}): {' '.join(clean_cmd)}")
            result_clean = subprocess.run(clean_cmd, check=True, capture_output=False, text=True, timeout=300)
           
            # 构建翻译命令
            translate_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-logfile", str(self.output_dir / f"{orig_name}_translate.log"),
                str(project_dir)
            ]
           
            # 添加排除目录
            for dir_pattern in self.exclude_dirs:
                translate_cmd.extend(["-exclude", f"{project_dir.name}/{dir_pattern}"])
           
            # 添加排除文件模式（使用通配符）
            for file_pattern in self.exclude_files:
                translate_cmd.extend(["-exclude", f"**/{file_pattern}"])
           
            logger.info(f"开始翻译项目: {orig_name} (ID: {project_id})")
            logger.debug(f"翻译命令: {' '.join(translate_cmd)}")
           
            # 执行翻译（实时输出）
            start_time = time.time()
            result = subprocess.run(
                translate_cmd,
                check=True,
                capture_output=False,
                text=True,
                timeout=1800 # 30分钟超时
            )
            end_time = time.time()
           
            translate_duration = end_time - start_time
            logger.info(f"翻译完成: {orig_name}, 耗时: {translate_duration:.2f}秒")
           
            return True
           
        except subprocess.CalledProcessError as e:
            logger.error(f"翻译过程错误 - {orig_name} (ID: {project_id}): {e}")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"翻译超时 - {orig_name} (ID: {project_id})")
            return False
        except Exception as e:
            logger.error(f"翻译异常 - {orig_name} (ID: {project_id}): {e}")
            return False
    def generate_pdf_report(self, fpr_id_file, project_id, orig_name):
        """使用ReportGenerator生成PDF报告"""
        try:
            pdf_id_file = self.output_dir / f"{project_id}.pdf"
            report_cmd = [
                str(self.report_generator_path),
                "-source", str(fpr_id_file),
                "-format", "pdf",
                "-f", str(pdf_id_file)
            ]
           
            logger.info(f"生成PDF报告: {orig_name} (ID: {project_id})")
            logger.debug(f"报告命令: {' '.join(report_cmd)}")
           
            result = subprocess.run(
                report_cmd,
                check=True,
                capture_output=False,
                text=True,
                timeout=600 # 10分钟超时
            )
           
            if pdf_id_file.exists():
                # 重命名PDF文件回原名
                pdf_orig_file = self.output_dir / f"{orig_name}.pdf"
                os.rename(pdf_id_file, pdf_orig_file)
                logger.info(f"PDF文件重命名完成: {project_id}.pdf -> {orig_name}.pdf")
               
                file_size = pdf_orig_file.stat().st_size / (1024 * 1024) # MB
                logger.info(f"PDF报告生成成功: {orig_name}, 文件: {pdf_orig_file} ({file_size:.2f} MB)")
                return str(pdf_orig_file)
            else:
                logger.error(f"PDF报告生成失败: {orig_name}, 未生成文件")
                return None
               
        except subprocess.CalledProcessError as e:
            logger.error(f"PDF报告生成错误 - {orig_name} (ID: {project_id}): {e}")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"PDF报告生成超时 - {orig_name} (ID: {project_id})")
            return None
        except Exception as e:
            logger.error(f"PDF报告生成异常 - {orig_name} (ID: {project_id}): {e}")
            return None
    def run_scan(self, project_dir, project_id, orig_name):
        """执行单个项目的Fortify扫描"""
        logger.info(f"开始扫描项目: {orig_name} (ID: {project_id})")
       
        try:
            # 首先翻译项目
            if not self.translate_project(project_dir, project_id, orig_name):
                logger.error(f"项目 {orig_name} 翻译失败，跳过扫描")
                return None, None
           
            # 构建规则参数
            rules_arg = self.build_rules_argument()
           
            # 执行扫描
            fpr_id_file = self.output_dir / f"{project_id}.fpr"
            scan_cmd = [
                str(self.sourceanalyzer),
                "-b", project_id,
                "-scan",
                "-f", str(fpr_id_file),
                "-format", "fpr",
                "-mt", # 启用多线程扫描
                #"-Dcom.fortify.sca.ProjectRoot=.", # 设置项目根目录
                "-Dcom.fortify.sca.Xmx=2G", # 限制内存使用
                "-Dcom.fortify.sca.ThreadCount=2", # 限制扫描线程数
                "-Dcom.fortify.sca.limiters=600" # 设置扫描超时
            ]
           
            # 添加规则文件参数
            if rules_arg:
                scan_cmd.extend(["-rules", rules_arg])
           
            logger.info(f"执行扫描命令，项目: {orig_name} (ID: {project_id})")
            logger.info(f"扫描命令: {' '.join(scan_cmd)}")
           
            # 执行扫描（实时输出）
            start_time = time.time()
            result = subprocess.run(
                scan_cmd,
                check=True,
                capture_output=False,
                text=True,
                timeout=3600 # 1小时超时
            )
            end_time = time.time()
           
            scan_duration = end_time - start_time
            logger.info(f"扫描完成: {orig_name}, 耗时: {scan_duration:.2f}秒")
           
            if fpr_id_file.exists():
                # 生成PDF报告（使用ID文件）
                pdf_file = self.generate_pdf_report(fpr_id_file, project_id, orig_name)
               
                # 重命名FPR文件回原名
                fpr_orig_file = self.output_dir / f"{orig_name}.fpr"
                os.rename(fpr_id_file, fpr_orig_file)
                logger.info(f"FPR文件重命名完成: {project_id}.fpr -> {orig_name}.fpr")
               
                return str(fpr_orig_file), pdf_file
            else:
                logger.error(f"扫描失败: {orig_name}, 未生成结果文件")
                return None, None
               
        except subprocess.CalledProcessError as e:
            logger.error(f"扫描过程错误 - {orig_name} (ID: {project_id}): {e}")
            return None, None
        except subprocess.TimeoutExpired:
            logger.error(f"扫描超时 - {orig_name} (ID: {project_id})")
            return None, None
        except Exception as e:
            logger.error(f"扫描异常 - {orig_name} (ID: {project_id}): {e}")
            return None, None
    def generate_summary_report(self, scan_results):
        """生成扫描总结报告"""
        summary_file = Path(LOG_DIR) / "min_code_scan_summary.txt"
       
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("CodeAnalyzer小程序扫描总结报告\n")
            f.write("=" * 50 + "\n")
            f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"扫描项目总数: {len(scan_results)}\n")
           
            successful_scans = [r for r in scan_results if r['success']]
            failed_scans = [r for r in scan_results if not r['success']]
           
            f.write(f"成功扫描: {len(successful_scans)}\n")
            f.write(f"失败扫描: {len(failed_scans)}\n")
            f.write(f"使用的规则: {', '.join(self.javascript_rules)}\n\n")
           
            f.write("成功项目:\n")
            for result in successful_scans:
                f.write(f" - {result['project_name']}: FPR={result['fpr_file']}, PDF={result.get('pdf_file', 'N/A')}\n")
           
            if failed_scans:
                f.write("\n失败项目:\n")
                for result in failed_scans:
                    f.write(f" - {result['project_name']}: {result.get('error', '未知错误')}\n")
       
        logger.info(f"总结报告已生成: {summary_file}")
    def run_all_scans(self):
        """执行所有项目的扫描"""
        logger.info("开始批量扫描小程序项目")
       
        # 验证环境
        self.validate_environment()        
        # 获取所有项目
        all_projects = self.get_miniprogram_projects()
        if not all_projects:
            logger.warning("未找到任何小程序项目")
            return
       
        # 过滤已扫描完成的项目
        projects = []
        for proj in all_projects:
            fpr_file = self.output_dir / f"{proj.name}.fpr"
            pdf_file = self.output_dir / f"{proj.name}.pdf"
            if fpr_file.exists() or pdf_file.exists():
                logger.info(f"跳过已扫描项目: {proj.name}")
            else:
                projects.append(proj)
       
        if not projects:
            logger.info("所有项目已扫描完成，无需进一步处理")
            return
       
        logger.info(f"待扫描项目数: {len(projects)}")
       
        # 创建项目ID映射（处理中文名）
        project_to_id = {proj.name: f"{i:03d}" for i, proj in enumerate(projects)}
        logger.info(f"项目ID映射: {project_to_id}")
       
        scan_results = []
       
        # 使用线程池执行扫描
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有扫描任务
            future_to_project = {
                executor.submit(self.run_scan, project, project_to_id[project.name], project.name): project.name
                for project in projects
            }
           
            # 收集结果
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
                        logger.info(f"项目 {orig_name} 扫描成功")
                    else:
                        scan_results.append({
                            'project_name': orig_name,
                            'error': '扫描失败，未生成结果文件',
                            'success': False
                        })
                        logger.error(f"项目 {orig_name} 扫描失败")
                except Exception as e:
                    scan_results.append({
                        'project_name': orig_name,
                        'error': str(e),
                        'success': False
                    })
                    logger.error(f"项目 {orig_name} 执行异常: {e}")
       
        # 生成总结报告
        self.generate_summary_report(scan_results)
        logger.info("所有扫描任务完成")
def main():
    """主函数"""
    cfg = load_fortify_config()

    try:
        # 创建扫描器实例
        scanner = FortifyScanner(
            fortify_path=cfg["fortify_path"],
            result_dir=cfg["result_dir"],
            output_dir=cfg["output_dir"],
            report_generator_path=cfg["report_generator_path"],
            max_workers=cfg["max_workers"],
        )

        # 执行扫描
        scanner.run_all_scans()

    except Exception as e:
        logger.error(f"扫描过程发生错误: {e}")
        return 1

    return 0
if __name__ == "__main__":
    exit(main())