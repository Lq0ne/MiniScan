# -*- coding: utf-8 -*-
"""
Local file scanning: URL extraction, regex secret detection, and Excel reporting.

Classes
-------
FileProcessor   – scans a decompiled mini program source tree for URLs / secrets.
AsyncRequest    – async HTTP prober for discovered URLs.
ExcelWriter     – writes / appends result sheets to an .xlsx workbook.
"""
import asyncio
import logging
import mmap
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import filetype
import httpx
import pandas as pd
from tqdm.asyncio import tqdm
from urllib.parse import urljoin, urlparse

from miniscan.config import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _deduplicate(matches: list) -> list:
    """
    Remove duplicate rows from a list of [key1, key2, ...] records,
    deduplicating on the first two columns.
    """
    sorted_matches = sorted(matches, key=lambda x: (x[0], x[1]))
    seen: set = set()
    return [
        item
        for item in sorted_matches
        if (item[0], item[1]) not in seen and not seen.add((item[0], item[1]))
    ]


# ---------------------------------------------------------------------------
# FileProcessor
# ---------------------------------------------------------------------------

class FileProcessor:
    """Scans text files in a directory tree for leaked URLs and regex-matched secrets."""

    def __init__(self) -> None:
        config = Config()
        self.url_pattern = re.compile(bytes(config.url_pattern_raw, "utf-8"), re.VERBOSE)
        self._compiled_regex: dict = {
            name: re.compile(bytes(pattern, "utf-8"), re.VERBOSE)
            for name, pattern in config._regex_patterns.items()
        }
        self.paths: list = []
        self.regex_matches: list = []
        self.http_urls: list = []
        self.path_urls: list = []
        self.existing_matches: set = set()
        self.not_asyncio_http: list = config.not_asyncio_http
        self.lock = threading.Lock()

    # ------------------------------------------------------------------
    # File helpers
    # ------------------------------------------------------------------

    def is_text_file(self, filepath: str) -> bool:
        """Return True if the file appears to be plain text (not a binary image)."""
        try:
            kind = filetype.guess(filepath)
            if kind is None:
                return True
            if kind.mime.startswith("image/"):
                return False
            logger.info(f"Special file detected (likely binary or non-text): {filepath}")
        except Exception as e:
            logger.debug(f"Error guessing filetype for {filepath}: {e}")
            return True

    # ------------------------------------------------------------------
    # Per-file workers (called from ThreadPoolExecutor)
    # ------------------------------------------------------------------

    def process_urls(self, file_path: str) -> None:
        """Extract URL-like strings from a single file and add them to self.paths."""
        try:
            with open(file_path, "r", encoding="gb18030") as file:
                with mmap.mmap(file.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    unique_matches = {
                        match[0].decode("utf-8")
                        for match in self.url_pattern.findall(mm)
                    }
                    new_matches = [
                        m
                        for m in unique_matches
                        if m not in self.existing_matches
                        and not any(ext in m for ext in [".jpg", ".png", ".jpeg", ".gif"])
                    ]
                    with self.lock:
                        self.paths.extend([[file_path, m] for m in new_matches])
                        self.existing_matches.update(new_matches)
        except Exception as e:
            logger.debug(f"Error processing urls in {file_path}: {e}")

    def process_regex(self, file_path: str) -> None:
        """Apply all enabled regex rules to a file and collect matches."""
        try:
            with open(file_path, "r", encoding="gb18030") as file:
                with mmap.mmap(file.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    for regex_name, regex_pattern in self._compiled_regex.items():
                        unique_matches = set(regex_pattern.findall(mm))
                        with self.lock:
                            for match in unique_matches:
                                self.regex_matches.append([regex_name, match, file_path])
        except Exception as e:
            logger.debug(f"Error processing regex in {file_path}: {e}")

    # ------------------------------------------------------------------
    # Directory-level orchestration
    # ------------------------------------------------------------------

    def process_directory(self, dir_path: str, output_dir: str, title: str) -> None:
        """
        Scan an entire decompiled mini program source tree.

        Results are written to an Excel workbook at ``output_dir/<process_file>``.
        """
        logger.info("Start scanning for URLs and potential secrets")
        config = Config()

        file_paths = [
            os.path.join(root, file)
            for root, _dirs, files in os.walk(dir_path)
            for file in files
        ]
        text_files = [p for p in file_paths if self.is_text_file(p)]

        with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            for future in as_completed(
                executor.submit(self.process_urls, p) for p in text_files
            ):
                future.result()

        with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            for future in as_completed(
                executor.submit(self.process_regex, p) for p in text_files
            ):
                future.result()

        self.paths.sort(key=self._sort_key)
        self.regex_matches = _deduplicate(self.regex_matches)

        combined_urls = AsyncRequest().combine_urls(self.http_urls, self.path_urls)
        xlsx_path = os.path.join(output_dir, config.process_file)

        writer = ExcelWriter(xlsx_path)
        try:
            writer.write_sheet(self.paths, ["File Path", "Leaked URL"], "urls")
        except Exception as e:
            logger.debug(f"Error writing urls sheet: {e}")
            writer.write_sheet([["", ""]], ["File Path", "Leaked URL"], "urls")

        try:
            writer.append_sheet(self.regex_matches, ["Rule ID", "Matched Value", "File Path"], "keys")
        except Exception as e:
            logger.debug(f"Error appending keys sheet: {e}")
            writer.append_sheet([["", "", ""]], ["Rule ID", "Matched Value", "File Path"], "keys")

        try:
            writer.append_urls(combined_urls)
        except Exception as e:
            logger.debug(f"Error appending combined urls sheet: {e}")
            writer.append_urls([[""]])

        if config.asyncio_http_enabled:
            result_http = asyncio.get_event_loop().run_until_complete(
                AsyncRequest().filter_urls(combined_urls)
            )
            try:
                writer.append_sheet(result_http, ["Status Code", "Size", "URL"], "fuzz")
            except Exception as e:
                logger.debug(f"Error appending fuzz sheet: {e}")
                writer.append_sheet([["", "", ""]], ["Status Code", "Size", "URL"], "fuzz")

        logger.info(f"URL scan finished, results saved to {xlsx_path}")

    def _sort_key(self, item: list):
        """
        Sort URLs: full HTTP URLs first, then relative paths, then dotfile paths.
        Side effect: populates self.http_urls and self.path_urls for later fuzzing.
        """
        if item[1].startswith("http"):
            if all(excl not in item[1] for excl in self.not_asyncio_http):
                with self.lock:
                    self.http_urls.append(item[1])
                return 0, item[1]
        elif not item[1].startswith("."):
            with self.lock:
                self.path_urls.append(item[1])
            return 1, item[1]
        return 2, item[1]


# ---------------------------------------------------------------------------
# AsyncRequest
# ---------------------------------------------------------------------------

class AsyncRequest:
    """Combines extracted URLs and path fragments, then probes them asynchronously."""

    def __init__(self) -> None:
        self.combined_urls: list = []
        self.http_results: list = []

    def _extract_base_url(self, url: str) -> str:
        self.combined_urls.append(url)
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    def combine_urls(self, urls: list, paths: list) -> list:
        """Return the cartesian product of base URLs × discovered paths."""
        base_urls = {self._extract_base_url(url) for url in urls}
        combined = [urljoin(base, path.lstrip("/")) for base in base_urls for path in paths]
        self.combined_urls.extend(combined)
        return self.combined_urls

    async def _fetch(self, client: httpx.AsyncClient, url: str):
        try:
            response = await client.get(url, timeout=2)
            size = (
                len(response.content)
                if "Content-Length" not in response.headers
                else int(response.headers["Content-Length"])
            )
            return response.status_code, size, url
        except httpx.ReadTimeout:
            return "timeout", 0, url
        except httpx.HTTPError:
            return "error", 0, url

    async def filter_urls(self, urls: list) -> list:
        """Probe all URLs concurrently and return filtered results."""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                tasks = [asyncio.create_task(self._fetch(client, url)) for url in urls]
                results = []
                for result in tqdm(
                    await asyncio.gather(*tasks, return_exceptions=True),
                    total=len(tasks),
                ):
                    results.append(result)

            config = Config()
            self.http_results = [
                r
                for r in results
                if not isinstance(r, Exception) and r[0] not in config.not_asyncio_status
            ]
            self.http_results.sort(
                key=lambda x: (x[0], x[1], x[2])
                if isinstance(x[0], int)
                else (float("inf"), x[1], x[2])
            )
            return self.http_results
        except Exception as e:
            logger.error(str(e))


# ---------------------------------------------------------------------------
# ExcelWriter
# ---------------------------------------------------------------------------

class ExcelWriter:
    """Writes pandas DataFrames to sheets in an openpyxl-backed .xlsx workbook."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path

    def append_urls(self, data: list) -> None:
        df = pd.DataFrame({"URL": pd.Series(data)})
        try:
            with pd.ExcelWriter(
                self.file_path, engine="openpyxl", mode="a", if_sheet_exists="overlay"
            ) as writer:
                df.to_excel(writer, sheet_name="拼接", index=False)
        except FileNotFoundError:
            with pd.ExcelWriter(self.file_path, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name="combined", index=False)

    def write_sheet(self, data: list, columns: list, sheet_name: str) -> None:
        df = pd.DataFrame.from_records(data)
        df.columns = columns
        with pd.ExcelWriter(self.file_path, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)

    def append_sheet(self, data: list, columns: list, sheet_name: str) -> None:
        df = pd.DataFrame.from_records(data)
        df.columns = columns
        try:
            with pd.ExcelWriter(
                self.file_path, engine="openpyxl", mode="a", if_sheet_exists="overlay"
            ) as writer:
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        except FileNotFoundError:
            with pd.ExcelWriter(self.file_path, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name=sheet_name, index=False)
