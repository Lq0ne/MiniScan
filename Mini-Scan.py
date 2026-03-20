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
import queue
import pandas as pd
import logging
import fortify_scan
from tqdm.asyncio import tqdm
from urllib.parse import urljoin, urlparse
from yaml import safe_load
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed
from path_utils import get_config_path, get_tools_path, get_base_dir, ensure_dir_exists

requests.packages.urllib3.disable_warnings()

# Configure logging   将该log存至Output/Log/scan_results.log中
log_dir = ensure_dir_exists(os.path.join(get_base_dir(), "Output", "Log"))
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'scan_results.log'), encoding='utf-8'),
        #logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        config_path = get_config_path("config.yaml")
        try:
            config = safe_load(open(config_path, "r", encoding="gb18030").read())
        except:
            config = safe_load(open(config_path, "r", encoding="utf-8").read())

        # Load settings from mini_scan section
        mini_scan_cfg = config.get("mini_scan", {})
        self.wx_dir = mini_scan_cfg.get("wx_dir", "")
        # Output directory for decompiled mini program sources (relative to base_dir or absolute path)
        output_dir_config = mini_scan_cfg.get("output_dir", "./Output/Source")
        if os.path.isabs(output_dir_config):
            self.output_dir = output_dir_config
        else:
            self.output_dir = os.path.join(get_base_dir(), output_dir_config)
        self.asyncio_http_enabled = mini_scan_cfg.get("asyncio_http_enabled", False)
        self.process_file = mini_scan_cfg.get("process_file", "Key.xlsx")
        self.wx_cmd_timeout = mini_scan_cfg.get("wx_cmd_timeout", 100)
        self.not_asyncio_http = mini_scan_cfg.get("not_asyncio_http", [])
        self.not_asyncio_status = mini_scan_cfg.get("not_asyncio_status", [])
        self.max_workers = mini_scan_cfg.get("max_workers", 5)

        self.req_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.8',
        }

        # Load regex rules from rule.yaml
        rule_path = get_config_path("rule.yaml")
        try:
            rule_config = safe_load(open(rule_path, "r", encoding="utf-8").read())
            rules = rule_config.get("rules", [])
            self._regex_patterns = {
                rule["id"]: rule["pattern"] 
                for rule in rules 
                if rule.get("enabled", False) and rule.get("pattern", "")
            }
        except:
            self._regex_patterns = {}

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
            logger.info(f"Special file detected (likely binary or non-text): {filepath}")
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
        logger.info("Start scanning for URLs and potential secrets")
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
            ExcelWriter(xlsx_path).write_sheet(self.paths, ['File Path', 'Leaked URL'], "urls")
        except:
            ExcelWriter(xlsx_path).write_sheet([["", ""]], ['File Path', 'Leaked URL'], "urls")

        try:
            ExcelWriter(xlsx_path).append_sheet(self.regex_matches, ['Rule ID', 'Matched Value', 'File Path'], "keys")
        except:
            ExcelWriter(xlsx_path).append_sheet([["", "", ""]], ['Rule ID', 'Matched Value', 'File Path'], "keys")

        try:
            ExcelWriter(xlsx_path).append_urls(combined_urls)
        except:
            ExcelWriter(xlsx_path).append_urls([[""]])

        if Config().asyncio_http_enabled:
            result_http = asyncio.get_event_loop().run_until_complete(AsyncRequest().filter_urls(combined_urls))
            try:
                ExcelWriter(xlsx_path).append_sheet(result_http, ['Status Code', 'Size', 'URL'], "fuzz")
            except:
                ExcelWriter(xlsx_path).append_sheet([["", "", ""]], ['Status Code', 'Size', 'URL'], "fuzz")

        logger.info(f"URL scan finished, results saved to {xlsx_path}")

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
        df = pd.DataFrame({'URL': pd.Series(data)})
        try:
            with pd.ExcelWriter(self.file_path, engine="openpyxl", mode='a', if_sheet_exists="overlay") as writer:
                df.to_excel(writer, sheet_name='拼接', index=False)
        except FileNotFoundError:
            with pd.ExcelWriter(self.file_path, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name='combined', index=False)

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
        wx_dir = Config().wx_dir
        if not wx_dir:
            logger.error("wx_dir is not configured in config.yaml (mini_scan.wx_dir)")
            sys.exit(0)
        self.applet_dir = os.path.join(wx_dir)
        self.unpack_tool = get_tools_path("KillWxapkg.exe")
        # used by monitor mode (batch decompile)
        self._seen_cache_dirs = set()

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
                    logger.error("Decompiled result directory is empty, retrying...")
                    success = False
                    retry += 1
            except subprocess.TimeoutExpired:
                logger.error("Unpack tool timed out, stopping this attempt")
                success = True
            except subprocess.CalledProcessError:
                logger.error("Unpack command failed, retrying...")
                retry += 1

        if not success:
            logger.error("Reached maximum retry count, giving up on this mini program")
            return True

        return False

    def _safe_mini_title(self):
        """
        Try to get current mini program window title, fallback to HintWnd-<random>.
        Keep existing logging habits.
        """
        try:
            wx_info = WxHook().get_wechat_info()
            title, pid, proc_name = wx_info[0]
        except:
            title, pid, proc_name = "HintWnd", "", ""

        if title == "HintWnd":
            logger.info("\nDetected HintWnd window title, failed to capture mini program name, using random suffix instead")
            title = title + "-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        return title

    def _detect_new_cache_dirs(self,before,timeout=0.2):
        """
        Detect newly created cache dirs under wx_dir. Return folder names list.
        """
        try:
            # if not self._seen_cache_dirs:
            #     before = {}
            #     self._seen_cache_dirs = {entry.name for entry in os.scandir(self.applet_dir) if entry.is_dir()}
            #     sleep(timeout)
            #     return []
            while 1:
                self._seen_cache_dirs = {entry.name for entry in os.scandir(self.applet_dir) if entry.is_dir()}
                # before = set(self._seen_cache_dirs)
                sleep(timeout)
                after = self._seen_cache_dirs - before
                before = self._seen_cache_dirs
                new_folders = list(after)
                if new_folders:
                    return new_folders
                else:
                    continue
        except Exception as e:
            logger.error(f"WxTools/_detect_new_cache_dirs bug: {e}")
            return []

    def _decompile_and_local_scan(self, folder, title, log_verbose=True):
        """
        Decompile one mini program cache folder and run local analysis.
        Returns (success: bool, output_dir: str|None)
        """
        try:
            result_dir = ensure_dir_exists(Config().output_dir)
            output_dir = os.path.join(result_dir, title)
            wxapkg_path = self.find_wxapkg(os.path.join(self.applet_dir, folder))

            if os.path.isdir(output_dir):
                if log_verbose:
                    logger.info(f"\nMini program \"{title}\" already exists, skipping decompile")
                return True, output_dir

            if log_verbose:
                logger.info(f"Detected new mini program window \"{title}\", starting decompile")

            os.mkdir(output_dir)
            cmd = f"{self.unpack_tool} -id=\"{folder}\" -in=\"{wxapkg_path}\" -restore -pretty -out \"{output_dir}\""
            unpack_failed = self.run_unpack(cmd, output_dir)

            if unpack_failed:
                file_count = sum(len(files) for _, _, files in os.walk(wxapkg_path))
                if file_count <= 1:
                    logger.error("No wxapkg encrypted file generated, very likely a network issue")
                else:
                    logger.error("wxapkg encrypted file exists but decompile failed, please open an issue with details")
                os.rmdir(output_dir)
                self.clean_wx_dirs()
                return False, None

            if log_verbose:
                logger.info(f"Decompile finished, source output directory: {output_dir}")

            # Local analysis (URL/secret extraction)
            try:
                FileProcessor().process_directory(output_dir, output_dir, title)
                return True, output_dir
            except Exception as e:
                logger.error(f"Local scan failed for \"{title}\": {e}")
                return False, output_dir
        except Exception as e:
            logger.error(f"WxTools/_decompile_and_local_scan bug: {e}")
            return False, None

    # --testing 模式：实时反编译 + 本地敏感信息扫描（可选 hook）
    def testing_mode_monitor(self, timeout=0.2):
        try:
            original_dirs = {entry.name for entry in os.scandir(self.applet_dir) if entry.is_dir()}
            sleep(timeout)
            new_dirs = {entry.name for entry in os.scandir(self.applet_dir) if entry.is_dir()}
            new_folders = new_dirs - original_dirs

            for folder in new_folders:
                title = self._safe_mini_title()
                ok, output_dir = self._decompile_and_local_scan(folder, title, log_verbose=True)
                if ok and args.devtools_hook:
                    thread = threading.Thread(target=run_wechat_hook, daemon=True)
                    thread.start()
        except Exception as e:
            logger.error(f"WxTools/testing_mode_monitor bug: {e}")

    # --monitor 模式：持续监控新小程序，直到用户输入 start，才批量反编译（可并发）
    def monitor_mode_monitor(self, timeout=0.2):
        """
        Behavior:
        - Continuously detect new cache folders and enqueue them (no decompile immediately).
        - When user types 'start', decompile ALL queued folders with concurrency=args.rate (default 2).
        - During batch decompile, log only per-app completion (success/fail) and local scan completion (success/fail).
        - After the batch, trigger a single Fortify scan for all projects under Output/Source (single-threaded here).
        """
        # folder -> title (capture title at detection time for stable naming)
        pending = {}
        pending_lock = threading.Lock()
        start_event = threading.Event()

        def input_worker():
            while True:
                try:
                    cmd = sys.stdin.readline()
                    if not cmd:
                        continue
                    if cmd.strip().lower() == "start":
                        start_event.set()
                except Exception:
                    # keep waiting
                    pass

        t = threading.Thread(target=input_worker, daemon=True)
        t.start()

        logger.info("Monitor mode initialized. Watching new mini programs. Type 'start' to batch decompile.")

        def if_main_apkg(folder):
            """
            递归查找当前文件夹中是否包含__APP__.wxapkg文件，包含返回true，否则false
            """
            folder = os.path.join(self.applet_dir, folder)
            for root, dirs, files in os.walk(folder):
                if "__APP__.wxapkg" in files:
                    return True
            return False

        before = set()#屎山代码至乱用全局变量（不知道咋写了哥）
        while True:
            # 1) keep collecting new folders
            try:
                new_folders = self._detect_new_cache_dirs(before, timeout=timeout)
                if new_folders:
                    with pending_lock:
                        for f in new_folders:
                            if f not in pending and if_main_apkg(f):
                                title = self._safe_mini_title()
                                pending[f] = title
                                logger.info(f"Detected new mini program \"{title}\" (queued). Pending: {len(pending)}")
            except Exception as e:
                logger.error(f"Monitor mode collect error: {e}")

            # 2) when user triggers start -> batch process snapshot
            if start_event.is_set():
                with pending_lock:
                    batch = dict(pending)
                    pending.clear()
                start_event.clear()

                if not batch:
                    logger.info("No pending mini programs detected. Continue monitoring...")
                    continue

                rate = getattr(args, "rate", 2) or 2
                try:
                    rate = int(rate)
                except Exception:
                    rate = 2
                if rate < 1:
                    rate = 1

                logger.info(f"Start batch decompile: total={len(batch)}, rate={rate}")

                def worker(folder, title):
                    ok, out_dir = self._decompile_and_local_scan(folder, title, log_verbose=False)
                    return folder, title, ok, out_dir

                results = []
                with ThreadPoolExecutor(max_workers=rate) as executor:
                    futures = [executor.submit(worker, f, title) for f, title in batch.items()]
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

                # Fortify scan (single run)
                logger.info("Monitor mode: triggering Fortify scan for all projects under Output/Source")
                try:
                    fortify_scan.main()
                except Exception as e:
                    logger.error(f"Fortify scan failed in monitor mode: {e}")

class WxHook:
    def __init__(self, js_path=None):
        if js_path is None:
            js_path = get_tools_path("WeChatAppEx.exe.js")
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
            logger.error("No WeChat mini program window detected")

def on_message_handler(message, data):
    if message['type'] == 'send':
        logger.info(f"[*] {message['payload']}")
    else:
        logger.info(str(message))

def run_wechat_hook():
    WxHook().attach_hook(on_message_handler)

def parse_arguments():
    try:
        parser = argparse.ArgumentParser(
            description='MiniScan: WeChat Mini Program decompiler and security auditor'
        )
        mode_group = parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument(
            '--scan-all',
            dest='scan_all',
            action='store_true',
            help='Scan all existing decompiled mini program sources under Output/Source using Fortify only'
        )
        mode_group.add_argument(
            '--monitor',
            dest='monitor',
            action='store_true',
            help='Monitor WeChat mini program windows, decompile in real time, run local analysis and Fortify scan'
        )
        mode_group.add_argument(
            '--testing',
            dest='testing',
            action='store_true',
            help='Monitor WeChat mini program windows and decompile in real time, run local analysis only (no Fortify scan)'
        )

        # Global options
        parser.add_argument(
            '-hook', '--hook',
            dest='devtools_hook',
            action='store_true',
            help='Enable Frida hook and open DevTools for the mini program process (only allowed with --testing mode)'
        )

        # Monitor mode options
        parser.add_argument(
            '--rate',
            '--thread',
            dest='rate',
            type=int,
            default=2,
            help='[monitor only] batch decompile concurrency (default: 2). Alias: --thread'
        )

        args = parser.parse_args()

        # Derive a simple mode string for downstream logic and display
        if args.scan_all:
            args.mode = "scan-all"
        elif args.monitor:
            args.mode = "monitor"
        elif args.testing:
            args.mode = "testing"
        else:
            args.mode = "unknown"

        # Validate that --hook is only used together with --testing
        if args.devtools_hook and args.mode != "testing":
            logger.error("--hook can only be used together with --testing mode")
            print("ERROR: --hook can only be used together with --testing mode")
            sys.exit(1)

        # Validate that --rate/--thread is only used with --monitor
        if args.rate != 2 and args.mode != "monitor":
            logger.error("--rate/--thread can only be used together with --monitor mode")
            print("ERROR: --rate/--thread can only be used together with --monitor mode")
            sys.exit(1)

        return args
    except Exception as e:
        logger.error(f"parse_arguments bugs: {e}")

if __name__ == "__main__":
    global args
    args = parse_arguments()
    mode_display = args.mode.upper()
    print(f'''
░█▄█░▀█▀░█▀█░▀█▀░░░█▀▀░█▀▀░█▀█░█▀█░░░█░█░▀█░░░░░▀█░
░█░█░░█░░█░█░░█░░░░▀▀█░█░░░█▀█░█░█░░░▀▄▀░░█░░░░░░█░
░▀░▀░▀▀▀░▀░▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░▀░▀░░░░▀░░▀▀▀░▀░░▀▀▀
  MiniScan V1.1 Author: Lq0ne Contributor: Xiaolin
        Mode: {mode_display}
    ''') # Pagga字体

    # Mode: scan-all -> run Fortify scan only, then exit
    if args.mode == "scan-all":
        logger.info("Running in SCAN-ALL mode: scanning all projects under Output/Source with Fortify")
        exit_code = fortify_scan.main()
        sys.exit(exit_code)

    # Modes that require WeChat monitoring
    wx_tools = WxTools()

    if args.mode == "monitor":
        # Ask user for confirmation before cleaning WeChat mini program cache directories
        print(
            "\n[WARNING] Monitor mode can remove WeChat mini program cache folders under the configured wx_dir.\n"
            "This will force WeChat to regenerate mini program packages on next launch.\n"
            "Do you want to clean existing mini program cache folders now? (they will be deleted recursively)\n"
        )
        choice = input("Type 'Y' to proceed with cleanup, or anything else to cancel: ").strip().lower()
        if choice == "y":
            logger.info("User confirmed wx_dir cleanup. Cleaning WeChat mini program cache folders...")
            wx_tools.clean_wx_dirs()
            logger.info("wx_dir cleanup finished. Existing mini program cache folders were removed.")
        else:
            sys.exit(0)

    logger.info(f"Mini-Scan initialized in mode: {args.mode}\n")

    # In monitor/testing modes, watch WeChat mini program windows continuously
    while True:
        if args.mode == "testing":
            wx_tools.testing_mode_monitor()
        elif args.mode == "monitor":
            wx_tools.monitor_mode_monitor()
        else:
            sleep(1)