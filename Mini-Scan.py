# -*- coding: utf-8 -*-
import argparse
import os
import mmap
import random
import re
import string
import filetype
import requests
import shutil
import subprocess
import win32gui
import win32process
import psutil
import frida
import sys
import asyncio
import httpx
import threading
import pandas as pd
import logging
import queue
import fortify_scan
from tqdm.asyncio import tqdm
from urllib.parse import urljoin, urlparse
from yaml import safe_load
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

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
        logging.FileHandler(os.path.join(LOG_DIR, 'main.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        # load main configuration
        config_path = os.path.join(CONFIG_DIR, "config.yaml")
        with open(config_path, "r", encoding="utf-8") as f:
            config = safe_load(f)

        mini_cfg = config.get("mini_scan", {})
        self.wx_dir = mini_cfg.get("wx_dir", "")
        self.asyncio_http_enabled = mini_cfg.get("asyncio_http_enabled", False)
        self.process_file = mini_cfg.get("process_file", "proess.xlsx")
        self.wx_cmd_timeout = mini_cfg.get("wx_cmd_timeout", 30)
        self.not_asyncio_http = mini_cfg.get("not_asyncio_http", [])
        self.not_asyncio_status = mini_cfg.get("not_asyncio_status", [404])
        self.max_workers = mini_cfg.get("max_workers", 5)
        self.unpack_tool = mini_cfg.get("unpack_tool", r".\tools\KillWxapkg.exe")
        self.pretty_default = mini_cfg.get("pretty_default", True)

        self.req_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.8',
        }

        # load regex rules from config/rule.yaml
        rules_path = os.path.join(CONFIG_DIR, "rule.yaml")
        self._regex_patterns = {}
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                rule_cfg = safe_load(f) or {}
            rules = rule_cfg.get("rules", [])
            for rule in rules:
                if rule.get("enabled") and rule.get("pattern"):
                    self._regex_patterns[rule.get("id")] = rule.get("pattern")
        except Exception as e:
            logger.error(f"加载规则文件失败: {e}")

        self.url_pattern_raw = r"""
          (?:"|')
          (
            ((?:[a-zA-Z]{1,10}://|//)
            [^"'/]{1,}\.
            [a-zA-Z]{2,}[^"']{0,})
            |
            ((?:/|\.\./|\./)
            [^"'><,;| *()(%%$^/\\\[\]]
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

class FileProcessor:
    def __init__(self):
        config = Config()
        self.url_pattern = re.compile(bytes(config.url_pattern_raw, 'utf-8'), re.VERBOSE)
        self._compiled_regex = {name: re.compile(bytes(pattern, "utf-8"), re.VERBOSE) for name, pattern in config._regex_patterns.items()}
        self.paths = []
        self.regex_matches = []
        self.http_urls = []
        self.path_urls = []
        self.existing_matches = set()
        self.not_asyncio_http = config.not_asyncio_http
        self.lock = threading.Lock()

    def is_text_file(self, filepath):
        try:
            kind = filetype.guess(filepath)
            if kind is None:
                return True
            if kind.mime.startswith('image/'):
                return False
            logger.info(f"特殊文件：{filepath}")
        except:
            return True

    def process_urls(self, file_path):
        try:
            with open(file_path, 'r', encoding="gb18030") as file:
                with mmap.mmap(file.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    unique_matches = {match[0].decode('utf-8') for match in self.url_pattern.findall(mm)}
                    new_matches = [match for match in unique_matches if match not in self.existing_matches and not any(ext in match for ext in [".jpg", ".png", ".jpeg", ".gif"])]
                    with self.lock:
                        self.paths.extend([[file_path, match] for match in new_matches])
                        self.existing_matches.update(new_matches)
        except Exception as e:
            pass

    def process_regex(self, file_path):
        try:
            with open(file_path, 'r', encoding="gb18030") as file:
                with mmap.mmap(file.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    for regex_name, regex_pattern in self._compiled_regex.items():
                        matches = {match for match in regex_pattern.findall(mm)}
                        unique_matches = set(matches)
                        with self.lock:
                            for match in unique_matches:
                                self.regex_matches.append([regex_name, match, file_path])
        except Exception as e:
            pass

    def process_directory(self, dir_path, output_dir, title):
        logger.info("开始搜索接口和泄露")
        file_paths = [
            os.path.join(root, file)
            for root, dirs, files in os.walk(dir_path)
            for file in files
        ]

        text_files = [path for path in file_paths if self.is_text_file(path)]

        with ThreadPoolExecutor(max_workers=Config().max_workers) as executor:
            futures = [executor.submit(self.process_urls, path) for path in text_files]
            for future in as_completed(futures):
                future.result()

        with ThreadPoolExecutor(max_workers=Config().max_workers) as executor:
            futures = [executor.submit(self.process_regex, path) for path in text_files]
            for future in as_completed(futures):
                future.result()

        def deduplicate(matches):
            sorted_matches = sorted(matches, key=lambda x: (x[0], x[1]))
            seen = set()
            return [item for item in sorted_matches if (item[0], item[1]) not in seen and not seen.add((item[0], item[1]))]

        self.paths.sort(key=self.custom_sort_key)
        self.regex_matches = deduplicate(self.regex_matches)

        combined_urls = AsyncRequest().combine_urls(self.http_urls, self.path_urls)
        xlsx_path = os.path.join(output_dir, Config().process_file)
        try:
            ExcelWriter(xlsx_path).write_sheet(self.paths, ['文件位置', '泄露地址'], "接口")
        except:
            ExcelWriter(xlsx_path).write_sheet([["", ""]], ['文件位置', '泄露地址'], "接口")

        try:
            ExcelWriter(xlsx_path).append_sheet(self.regex_matches, ['文件位置', '泄露key', '泄露内容'], "key")
        except:
            ExcelWriter(xlsx_path).append_sheet([["", "", ""]], ['文件位置', '泄露key', '泄露内容'], "key")

        try:
            ExcelWriter(xlsx_path).append_urls(combined_urls)
        except:
            ExcelWriter(xlsx_path).append_urls([[""]])

        if Config().asyncio_http_enabled:
            result_http = asyncio.get_event_loop().run_until_complete(AsyncRequest().filter_urls(combined_urls))
            try:
                ExcelWriter(xlsx_path).append_sheet(result_http, ['状态码', '大小', '接口url'], "fuzz")
            except:
                ExcelWriter(xlsx_path).append_sheet([["", "", ""]], ['状态码', '大小', '接口url'], "fuzz")

        logger.info(f"接口请求完成,文件保存到{xlsx_path}")

    def custom_sort_key(self, item):
        if item[1].startswith("http"):
            if all(not_http not in item[1] for not_http in self.not_asyncio_http):
                with self.lock:
                    self.http_urls.append(item[1])
                return 0, item[1]
        elif not item[1].startswith('.'):
            with self.lock:
                self.path_urls.append(item[1])
            return 1, item[1]
        return 2, item[1]

class AsyncRequest:
    def __init__(self):
        self.combined_urls = []
        self.http_results = []

    def extract_base_url(self, url):
        self.combined_urls.append(url)
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    def combine_urls(self, urls, paths):
        base_urls = {self.extract_base_url(url) for url in urls}
        combined = [urljoin(base, path.lstrip('/')) for base in base_urls for path in paths]
        for url in combined:
            self.combined_urls.append(url)
        return self.combined_urls

    async def fetch(self, client, url):
        try:
            response = await client.get(url, timeout=2)
            status = response.status_code
            size = len(response.content) if 'Content-Length' not in response.headers else int(response.headers['Content-Length'])
            return status, size, url
        except httpx.ReadTimeout:
            return "timeout", 0, url
        except httpx.HTTPError:
            return "error", 0, url

    async def filter_urls(self, urls):
        try:
            async with httpx.AsyncClient(verify=False) as client:
                tasks = [asyncio.create_task(self.fetch(client, url)) for url in urls]
                results = []
                for result in tqdm(await asyncio.gather(*tasks, return_exceptions=True), total=len(tasks)):
                    results.append(result)

            self.http_results = [r for r in results if not isinstance(r, Exception) and r[0] not in Config().not_asyncio_status]
            self.http_results.sort(key=lambda x: (x[0], x[1], x[2]) if isinstance(x[0], int) else (float('inf'), x[1], x[2]))
            return self.http_results
        except Exception as e:
            logger.error(str(e))

class ExcelWriter:
    def __init__(self, file_path):
        self.file_path = file_path

    def append_urls(self, data):
        df = pd.DataFrame({'接口': pd.Series(data)})
        try:
            with pd.ExcelWriter(self.file_path, engine="openpyxl", mode='a', if_sheet_exists="overlay") as writer:
                df.to_excel(writer, sheet_name='拼接', index=False)
        except FileNotFoundError:
            with pd.ExcelWriter(self.file_path, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name='拼接', index=False)

    def write_sheet(self, data, columns, sheet_name):
        df = pd.DataFrame.from_records(data)
        df.columns = columns
        with pd.ExcelWriter(self.file_path, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)

    def append_sheet(self, data, columns, sheet_name):
        df = pd.DataFrame.from_records(data)
        df.columns = columns
        try:
            with pd.ExcelWriter(self.file_path, engine="openpyxl", mode='a', if_sheet_exists="overlay") as writer:
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        except FileNotFoundError:
            with pd.ExcelWriter(self.file_path, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name=sheet_name, index=False)

class WxTools:
    def __init__(self):
        self._cfg = Config()
        wx_dir = self._cfg.wx_dir
        if not wx_dir:
            logger.error("未配置wx文件夹")
            sys.exit(0)
        self.applet_dir = os.path.join(wx_dir)
        self.unpack_tool = self._cfg.unpack_tool
        self.pretty_default = self._cfg.pretty_default

    def clean_wx_dirs(self):
        try:
            with os.scandir(self.applet_dir) as entries:
                for entry in entries:
                    if entry.is_dir() and entry.name.startswith('wx') and len(entry.name) == 18:
                        shutil.rmtree(entry.path)
        except Exception as e:
            logger.error(str(e))

    def find_wxapkg(self, path):
        current = path
        while True:
            entries = os.listdir(current)
            dirs = [entry for entry in entries if os.path.isdir(os.path.join(current, entry))]
            if not dirs:
                return current
            current = os.path.join(current, dirs[0])

    def run_unpack(self, command, output_dir, max_retries=5):
        retry = 0
        success = False
        while retry < max_retries and not success:
            try:
                subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=Config().wx_cmd_timeout)
                file_count = sum(len(files) for _, _, files in os.walk(output_dir))
                if file_count > 2:
                    success = True
                else:
                    logger.error("出现错误反编译为空，正在重试")
                    success = False
                    retry += 1
            except subprocess.TimeoutExpired:
                logger.error("反编译执行超时，停止运行")
                success = True
            except subprocess.CalledProcessError:
                logger.error("命令行反编译工具出现错误，正在重试")
                retry += 1

        if not success:
            logger.error("达到最大重试次数，停止该次循环")
            return True

        return False

    def monitor_new_applet(self, timeout=0.2):
        try:
            original_dirs = {entry.name for entry in os.scandir(self.applet_dir) if entry.is_dir()}
            sleep(timeout)
            new_dirs = {entry.name for entry in os.scandir(self.applet_dir) if entry.is_dir()}
            new_folders = new_dirs - original_dirs

            for folder in new_folders:
                # 获取小程序窗口信息，失败时重试一次
                title, pid, proc_name = "", "", ""
                for attempt in range(2):
                    try:
                        wx_info = WxHook().get_wechat_info()
                        if wx_info:
                            title, pid, proc_name = wx_info[0]
                            break
                    except Exception:
                        pass
                    sleep(0.5)
                if not title:
                    title, pid, proc_name = "HintWnd", "", ""
                if title == "HintWnd":
                    logger.info("\n检测到HintWnd，代表没有抓到小程序名，为不影响程序，这里使用随机数")
                    title = title + "-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                output_dir = os.path.join(SOURCE_DIR, title)
                wxapkg_path = self.find_wxapkg(os.path.join(self.applet_dir, folder))
                if os.path.isdir(output_dir):
                    logger.info(f"\n《{title}》文件已经存在")
                else:
                    logger.info(f"检测打开了 《{title}》小程序正在进行反编译")
                    os.makedirs(output_dir, exist_ok=True)

                    pretty_flag = "-pretty" if self.pretty_default else ""
                    cmd = f"{self.unpack_tool} -id=\"{folder}\" -in=\"{wxapkg_path}\" -restore {pretty_flag} -out \"{output_dir}\"".strip()

                    unpack_failed = self.run_unpack(cmd, output_dir)
                    if unpack_failed:
                        file_count = sum(len(files) for _, _, files in os.walk(wxapkg_path))
                        if file_count <= 1:
                            logger.error("没有生成对应的wxapkg加密文件,大概率为网络问题")
                        else:
                            logger.error("存在wxapkg加密文件，没有反编译成功，请反馈issue")
                        os.rmdir(output_dir)
                        self.clean_wx_dirs()
                        break
                    logger.info(f"执行完毕-反编译源代码输出: {output_dir}")

                    if args.devtools_hook:
                        thread = threading.Thread(target=run_wechat_hook)
                        thread.start()

                    # 监控模式下，如配置启用Fortify，则在每次反编译后运行一次审计
                    cfg = safe_load(open(os.path.join(CONFIG_DIR, "config.yaml"), "r", encoding="utf-8"))
                    fortify_cfg = cfg.get("fortify_scan", {})
                    if fortify_cfg.get("enabled", True):
                        logger.info("开始执行 Fortify 扫描，等待扫描完成...")
                        ret = fortify_scan.main()
                        logger.info(f"Fortify 扫描完成，返回码: {ret}")

                    FileProcessor().process_directory(output_dir, output_dir, title)
        except Exception as e:
            logger.error(f"WxTools/monitor_new_applet bug: {e}")

class WxHook:
    def __init__(self, js_path=r"./tools/WeChatAppEx.exe.js"):
        self.hook_js = js_path
        self.session = None

    def get_wechat_info(self):
        try:
            info = []

            def callback(hwnd, extra):
                text = win32gui.GetWindowText(hwnd)
                if text:
                    pid = win32process.GetWindowThreadProcessId(hwnd)
                    proc = psutil.Process(pid[1])
                    if proc.name() == "WeChatAppEx.exe" and text not in ["微信", "MSCTFIME UI", "Default IME"]:
                        info.append((text, pid[1], proc.name()))

            win32gui.EnumWindows(callback, None)
            return info
        except Exception as e:
            logger.error(f"WxHook/get_wechat_info bug: {e}")

    def attach_hook(self, on_message_callback):
        info = self.get_wechat_info()
        if info:
            title, pid, proc_name = info[0]
            logger.info(f"Window Title: {title}, PID: {pid}, Process Name: {proc_name}")
            try:
                self.session = frida.attach(pid)
                with open(self.hook_js, 'r', encoding='utf8') as f:
                    script = self.session.create_script(f.read())

                script.on('message', on_message_callback)
                script.load()
                sys.stdin.read()
            except KeyboardInterrupt:
                logger.error('Detaching from process...')
            finally:
                if self.session is not None:
                    self.session.detach()
        else:
            logger.error("检测小程序没有打开")

def on_message_handler(message, data):
    if message['type'] == 'send':
        logger.info(f"[*] {message['payload']}")
    else:
        logger.info(str(message))

def run_wechat_hook():
    WxHook().attach_hook(on_message_handler)

def parse_arguments():
    try:
        parser = argparse.ArgumentParser(description='MiniScan: WeChat MiniProgram Decompiler and Auditor')
        mode_group = parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument(
            '-monitor', '--monitor',
            dest='monitor_mode',
            action='store_true',
            help='实时监控模式：监控新打开的小程序并自动反编译与审计'
        )
        mode_group.add_argument(
            '-scan', '--scan',
            dest='scan_mode',
            action='store_true',
            help='扫描模式：清空缓存后批量反编译当前所有已打开的小程序并统一进行审计'
        )
        parser.add_argument(
            '-hook', '--hook',
            dest='devtools_hook',
            action='store_true',
            help='启用hook, 打开devtools'
        )
        return parser.parse_args()
    except Exception as e:
        logger.error(f"parse_arguments bugs: {e}")


def run_monitor_mode(wx_tools: WxTools):
    logger.info("当前运行模式：实时监控模式 (monitor)")
    wx_tools.clean_wx_dirs()
    logger.info("Mini-Scan 初始化完成，开始监控小程序...\n")
    while True:
        wx_tools.monitor_new_applet()


def run_scan_mode(wx_tools: WxTools):
    logger.info("当前运行模式：扫描模式 (scan)")
    # 确认删除缓存目录
    confirm = input(
        f"扫描模式需要删除小程序缓存目录：{wx_tools.applet_dir}\n"
        f"请确认该目录内无重要文件。确认请输 Y，取消请输入 N： "
    ).strip().upper()
    if confirm != 'Y':
        logger.info("用户取消扫描模式，程序退出。")
        return

    # 删除小程序缓存目录
    logger.info("开始清理小程序缓存目录...")
    wx_tools.clean_wx_dirs()
    logger.info("缓存目录清理完成。")

    # 提示用户开启需要扫描的小程序，并实时监控记录
    cached_programs = {}
    # known_pids = set()
    known_dirs = {
        entry.name for entry in os.scandir(wx_tools.applet_dir)
        if entry.is_dir() and entry.name.startswith('wx')
    }
    print("当前为扫描模式，请依次在微信中打开需要扫描的小程序。")
    print("每次成功检测到小程序后终端会提示；全部开启完成后输入 Start，输入 Q 取消。")

    command_queue = queue.Queue()
    stop_event = threading.Event()

    def input_worker():
        while not stop_event.is_set():
            cmd = input("请输入指令(Start/Q)：").strip()
            command_queue.put(cmd)
            if cmd.lower() in ("start", "q"):
                break

    threading.Thread(target=input_worker, daemon=True).start()

    def capture_program_title():
        title = ""
        for _ in range(2):
            try:
                wx_info = WxHook().get_wechat_info() or []
                for info_title, pid, _ in wx_info:
                    # if pid in known_pids:
                        #continue
                    # known_pids.add(pid)
                    title = info_title
                    break
            except Exception:
                pass
            if title:
                break
            sleep(0.5)
        if not title:
            title = "HintWnd"
        if title == "HintWnd":
            logger.info("\n检测到HintWnd，代表没有抓到小程序名，为不影响程序，这里使用随机数")
            title = title + "-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        return title

    while True:
        current_dirs = {
            entry.name for entry in os.scandir(wx_tools.applet_dir)
            if entry.is_dir() and entry.name.startswith('wx')
        }
        new_dirs = [d for d in current_dirs if d not in known_dirs]
        for folder in new_dirs:
            known_dirs.add(folder)
            title = capture_program_title()
            cached_programs[folder] = title
            logger.info(f"已检测到第{len(cached_programs)}个小程序：{title} (wxid: {folder})")
        try:
            cmd = command_queue.get_nowait()
        except queue.Empty:
            cmd = None
        if cmd:
            cmd_lower = cmd.lower()
            if cmd_lower == "start":
                if not cached_programs:
                    print("尚未检测到任何小程序，请继续开启。")
                else:
                    stop_event.set()
                    break
            elif cmd_lower == "q":
                stop_event.set()
                logger.info("用户取消扫描模式，程序退出。")
                return
        sleep(0.5)

    # 收集所有小程序缓存目录
    folders = list(cached_programs.keys())
    if not folders:
        logger.warning("未检测到任何小程序，扫描结束。")
        return

    logger.info(f"开始批量反编译，共 {len(folders)} 个小程序，使用 1 个线程。")

    results = []

    def decompile_folder(folder_name):
        try:
            title = cached_programs.get(folder_name)
            if not title:
                # 与监控模式一致的窗口名获取和重试逻辑
                title, pid, proc_name = "", "", ""
                for attempt in range(2):
                    try:
                        wx_info = WxHook().get_wechat_info()
                        if wx_info:
                            title, pid, proc_name = wx_info[0]
                            break
                    except Exception:
                        pass
                    sleep(0.5)
                if not title:
                    title = "HintWnd"
                if title == "HintWnd":
                    logger.info("\n检测到HintWnd，代表没有抓到小程序名，为不影响程序，这里使用随机数")
                    title = title + "-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

            output_dir = os.path.join(SOURCE_DIR, title)
            wxapkg_path = wx_tools.find_wxapkg(os.path.join(wx_tools.applet_dir, folder_name))

            if os.path.isdir(output_dir):
                logger.info(f"《{title}》已存在，跳过反编译。")
                return title, "skipped"

            os.makedirs(output_dir, exist_ok=True)
            pretty_flag = "-pretty" if wx_tools.pretty_default else ""
            cmd = f"{wx_tools.unpack_tool} -id=\"{folder_name}\" -in=\"{wxapkg_path}\" -restore {pretty_flag} -out \"{output_dir}\"".strip()

            unpack_failed = wx_tools.run_unpack(cmd, output_dir)
            if unpack_failed:
                file_count = sum(len(files) for _, _, files in os.walk(wxapkg_path))
                if file_count <= 1:
                    logger.error(f"《{title}》没有生成对应的wxapkg加密文件, 大概率为网络问题")
                else:
                    logger.error(f"《{title}》存在wxapkg加密文件，没有反编译成功，请反馈issue")
                try:
                    os.rmdir(output_dir)
                except OSError:
                    pass
                return title, "failed"

            logger.info(f"执行完毕-反编译源代码输出: {output_dir}")
            return title, "success"
        except Exception as e:
            logger.error(f"批量反编译 {folder_name} 失败: {e}")
            return folder_name, "failed"

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=1) as executor:
        future_to_folder = {
            executor.submit(decompile_folder, folder): folder
            for folder in folders
        }
        for future in as_completed(future_to_folder):
            title, status = future.result()
            results.append((title, status))

    # 统计结果
    total = len(results)
    success = sum(1 for _, s in results if s == "success")
    failed = sum(1 for _, s in results if s == "failed")
    skipped = sum(1 for _, s in results if s == "skipped")

    logger.info(f"批量反编译完成，总计 {total} 个，小程序：成功 {success}，失败 {failed}，跳过 {skipped}。")

    # 反编译完成后统一进行 Fortify 审计与接口泄露扫描
    cfg = safe_load(open(os.path.join(CONFIG_DIR, "config.yaml"), "r", encoding="utf-8"))
    fortify_cfg = cfg.get("fortify_scan", {})
    if fortify_cfg.get("enabled", True):
        logger.info("开始执行 Fortify 扫描（批量），等待扫描完成...")
        ret = fortify_scan.main()
        logger.info(f"Fortify 扫描完成，返回码: {ret}")

    # 对所有已反编译项目执行接口和泄露扫描
    for entry in os.scandir(SOURCE_DIR):
        if entry.is_dir():
            title = entry.name
            src_dir = entry.path
            logger.info(f"开始对《{title}》进行接口与敏感信息扫描...")
            FileProcessor().process_directory(src_dir, src_dir, title)


if __name__ == "__main__":
    global args
    args = parse_arguments()
    print('''
░█▄█░▀█▀░█▀█░▀█▀░░░█▀▀░█▀▀░█▀█░█▀█░░░█░█░▄▀▄░░░░▀█░
░█░█░░█░░█░█░░█░░░░▀▀█░█░░░█▀█░█░█░░░▀▄▀░█/█░░░░░█░
░▀░▀░▀▀▀░▀░▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░▀░▀░░░░▀░░░▀░░▀░░▀▀▀
        MiniScan V0.1 Author: Lq0ne
    ''')
    wx_tools = WxTools()
    if args.monitor_mode:
        run_monitor_mode(wx_tools)
    elif args.scan_mode:
        run_scan_mode(wx_tools)