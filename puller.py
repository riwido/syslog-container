#!/usr/bin/env python3
from __future__ import annotations

import dataclasses
import ipaddress
import itertools
import logging
import logging.handlers
import os
import pathlib
import queue
import re
import socket
import subprocess
import sys
import threading

logger = logging.getLogger(__name__)


BASIC_FORMAT = dict(
    fmt="{levelname:<8}: {message}",
    style="{",
    validate=True,
)

BASIC_FORMAT_FILENAME = dict(
    fmt="{pathname}\n{levelname:<8}: {message}",
    style="{",
    validate=True,
)

DEBUG_FORMAT = dict(
    fmt="{asctime} - {name}:{levelname:<8}:{threadName}:{funcName}:{lineno} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M:%S",
    validate=True,
)

DEBUG_FORMAT_FILENAME = dict(
    fmt="{pathname}\n{asctime} - {name}:{levelname:<8}:{threadName}:{funcName}:{lineno} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M:%S",
    validate=True,
)


@dataclasses.dataclass
class FilterLogByModules:
    modules: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        self._filtered = {}

    def _is_name_filtered(self, name: str) -> bool:
        if not self.modules:
            return True
        for module in self.modules:
            if module in name:
                return True
        return False

    def filter(self, record: logging.LogRecord) -> bool:
        return self._filtered.setdefault(
            record.name,
            self._is_name_filtered(record.name),
        )


def get_log_level(level: int) -> int:
    if not level:
        level = logging.CRITICAL + 1

    elif level == 1:
        level = logging.CRITICAL

    elif level == 2:
        level = logging.ERROR

    elif level == 3:
        level = logging.WARNING

    elif level == 4:
        level = logging.INFO

    elif level >= 5:
        level = logging.DEBUG
    return level


def set_logger(
    verbose: int = logging.NOTSET,
    debug=False,
    log_file: str = None,
    log_file_level: int = logging.NOTSET,
    log_file_mb: int = 10,
    log_file_depth: int = 1,
    modules: list = None,
    include_path: bool = False,
):
    if modules is None:
        modules = []
    logger = logging.getLogger()
    while logger.handlers:
        logger.handlers.pop()
    stream_level = get_log_level(verbose)
    file_level = get_log_level(log_file_level)
    logger.setLevel(min(stream_level, file_level))

    log_filter = FilterLogByModules(modules)
    handler = logging.StreamHandler()
    handler.addFilter(log_filter)
    handler.setLevel(stream_level)

    if (stream_level is logging.DEBUG or debug) and include_path:
        log_format = DEBUG_FORMAT_FILENAME
    elif stream_level is logging.DEBUG or debug:
        log_format = DEBUG_FORMAT
    elif include_path:
        log_format = BASIC_FORMAT_FILENAME
    else:
        log_format = BASIC_FORMAT

    handler.setFormatter(logging.Formatter(**log_format))
    logger.addHandler(handler)

    if log_file:
        file_size_bytes = log_file_mb * 1024 * 1024
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=file_size_bytes,
            backupCount=log_file_depth,
        )
        file_handler.setLevel(file_level)
        file_handler.addFilter(log_filter)
        file_handler.setFormatter(logging.Formatter(**DEBUG_FORMAT_FILENAME))
        logger.addHandler(file_handler)

    if logger.level > logging.CRITICAL:
        logger.disabled = True


LOCK = threading.Lock()

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


HEALTH_FILE = "HEALTH_FILE"
REPORT_CYCLES = "REPORT_CYCLES"
QUEUE_LIMIT = "QUEUE_LIMIT"
MAX_WORKERS = "MAX_WORKERS"


envvars = dict(
    HEALTH_FILE=None,
    REPORT_CYCLES=None,
    QUEUE_LIMIT=None,
    MAX_WORKERS=None,
)

for varname in list(envvars.keys()):
    envvar = os.getenv(varname)
    if not envvar:
        raise RuntimeError(f"env variable {varname} required")
    envvars[varname] = envvar

def test_ip_address(host):
    # Filter out internal logs presented with host as 6 byte hex
    if re.match(r"[a-f0-9]{12}", host, re.I):
        logger.debug("Invalid IP Address due to mac pattern: %s", host)
        return
    try:
        logger.debug("Valid IP: %s", host)
        ipaddress.IPv4Address(host)
        return True
    except ipaddress.AddressValueError:
        logger.debug("Is not an IP address: %s", host)
        pass
    try:
        logger.debug("Valid FQDN: %s", host)
        if socket.gethostbyname(host):
            return True
    except socket.gaierror:
        logger.debug("Is not a valid FQDN: %s", host)
        pass



class Worker(threading.Thread):
    def __init__(
        self,
        jobs: queue.Queue,
        results: queue.Queue,
    ):
        self.jobs = jobs
        self.results = results
        self.stopped = False
        super().__init__()

    def run(self):
        while True:
            if self.stopped:
                break
            try:
                host = self.jobs.get(timeout=1)
            except queue.Empty:
                continue
            error = None
            try:
                logger.debug("%s: Work is beginning", host)
                logger.info(f"Work is being done to: {host}")
                logger.debug("%s: Work ended normally", host)
            except Exception as exc:
                error = str(exc)
                logger.debug("%s: Work ended with error: %s", host, error)
            finally:
                logger.debug("%s: Adding to results queue", host)
                self.results.put((host, error, True))
                logger.debug("%s: Added to results queue", host)


class ThreadPool(threading.Thread):
    def __init__(
        self,
        workers: int,
        jobs: queue.Queue,
        results: queue.Queue,
        healthfile: str,
    ):
        self.workers = workers
        self.jobs = jobs
        self.results = results
        self.healthfile = pathlib.Path(healthfile)
        self.stopped = False
        self._device_failure = False
        self._report_cycle = itertools.cycle(range(int(envvars[REPORT_CYCLES])))
        self._threads = []
        super().__init__()

    def _start_threads(self):
        for _ in range(self.workers):
            worker = Worker(self.jobs, self.results)
            worker.start()
            self._threads.append(worker)

    def _stop_threads(self):
        for worker in self._threads:
            worker.stopped = True

    def _report(self):
        if next(self._report_cycle):
            return
        subprocess.call(["touch", f"{envvars[HEALTH_FILE]}"])

    def run(self):
        self._start_threads()
        while True:
            # Stop if done
            if self.stopped:
                self._stop_threads()
                break

            # Report on healthstat
            self._report()

            # Collect results
            try:
                host, error, result = self.results.get(timeout=1)
            except queue.Empty:
                continue

            # Error caught by worker
            if error:
                logger.error(
                    "%s: Error received: %s",
                    host,
                    error,
                )
                self._device_failure = True
                logger.error(f"Error")
                continue


            # Process rules
            try:
                if not error:
                    logger.debug("%s: success", host)
                    self._device_failure = False
                else:
                    logger.debug(
                        "%s: not success: %s",
                        host,
                        error,
                    )

            # Error caught comparing and saving
            except Exception as exc:
                logger.debug(
                    "%s: exception: %s",
                    host,
                    str(exc),
                )
                self._device_failure = True


def main():
    subprocess.call(["touch", f"{envvars[HEALTH_FILE]}"])
    jobs = queue.Queue(maxsize=int(envvars[QUEUE_LIMIT]))
    results = queue.Queue()
    logger.info("Initialized")
    threadpool = ThreadPool(
        workers=int(envvars[MAX_WORKERS]),
        jobs=jobs,
        results=results,
        healthfile=envvars[HEALTH_FILE],
    )
    threadpool.start()
    try:
        while True:
            host = sys.stdin.readline()
            host = host.strip()
            if jobs.full():
                logger.error(f"queue is full.  failed: {host}")
                continue
            jobs.put(host)
    finally:
        threadpool.stopped = True

if __name__ == "__main__":
    exc = object()
    open('/tmp/puller-start.txt', 'w+').write(f"{type(exc).__name__}: {exc!s}")
    try:
        set_logger(log_file="/var/log/puller.log", log_file_level=5)
        logger.debug("hi")
        main()
    except Exception as exc:
        open('/tmp/puller-error.txt', 'w+').write(f"{type(exc).__name__}: {exc!s}")
