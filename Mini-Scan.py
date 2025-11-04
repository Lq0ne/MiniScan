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
from tqdm.asyncio import tqdm
from urllib.parse import urljoin, urlparse
from yaml import safe_load
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed
import fortify_scan

requests.packages.urllib3.disable_warnings()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('.\\results\\miniscan.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
        try:
            config = safe_load(open(config_path, "r", encoding="gb18030").read())
        except:
            config = safe_load(open(config_path, "r", encoding="utf-8").read())

        self.wx_dir = config["wx-tools"]["wx-file"]
        self.asyncio_http_enabled = config["tools"]["asyncio_http_tf"]
        self.process_file = config["tools"]["proess_file"]
        self.wx_cmd_timeout = config["tools"]["wxpcmd_timeout"]
        self.not_asyncio_http = config["tools"]["not_asyncio_http"]
        self.not_asyncio_status = config["tools"]["not_asyncio_stats"]
        self.max_workers = config["tools"]["max_workers"]

        self.req_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.8',
        }

        self._regex_patterns = config.get("rekey", {})

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
        wx_dir = Config().wx_dir
        if not wx_dir:
            logger.error("未配置wx文件夹")
            sys.exit(0)
        self.applet_dir = os.path.join(wx_dir, "Applet")
        self.unpack_tool = r".\tools\KillWxapkg.exe"

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
                logger.error("工具执行超时，停止运行")
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
                try:
                    wx_info = WxHook().get_wechat_info()
                    title, pid, proc_name = wx_info[0]
                except:
                    title, pid, proc_name = "HintWnd", "", ""
                if title == "HintWnd":
                    logger.info("\n检测到HintWnd，代表没有抓到小程序名，为不影响程序，这里使用随机数")
                    title = title + "-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                output_dir = f"./result/{title}"
                wxapkg_path = self.find_wxapkg(os.path.join(self.applet_dir, folder))
                if os.path.isdir(output_dir):
                    logger.info(f"\n《{title}》文件已经存在")
                else:
                    logger.info(f"检测打开了 《{title}》小程序正在进行反编译")
                    os.mkdir(output_dir)

                    if args.pretty_format:
                        cmd = f"{self.unpack_tool} -id=\"{folder}\" -in=\"{wxapkg_path}\" -restore -pretty -out \"{output_dir}\""
                    else:
                        cmd = f"{self.unpack_tool} -id=\"{folder}\" -in=\"{wxapkg_path}\" -restore -out \"{output_dir}\""

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

                    FileProcessor().process_directory(output_dir, output_dir, title)

                    if args.fortify_scan:
                        fortify_scan.main()

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
        parser.add_argument('-hook', '--hook', dest='devtools_hook', action='store_true', help='启用hook,打开devtools')
        parser.add_argument('-pretty', '--pretty', dest='pretty_format', action='store_true', help='启用代码优化,优化输出代码格式,注意部分小程序美化可能需较长时间')
        parser.add_argument('-scan', '--scan', dest='fortify_scan', action='store_true', help='启用Fortify扫描,进行小程序前端源码代码审计')
        args = parser.parse_args()
        return args
    except Exception as e:
        logger.error(f"parse_arguments bugs: {e}")

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
    wx_tools.clean_wx_dirs()
    logger.info("Mini-Scan初始化完成\n")
    while True:
        wx_tools.monitor_new_applet()