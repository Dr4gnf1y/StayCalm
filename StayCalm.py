import ast
import asyncio
import atexit
import concurrent.futures
import importlib.util
import ipaddress
import itertools
import json
import logging
import logging.config
import logging.handlers
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import (ProcessPoolExecutor, ThreadPoolExecutor,
                                as_completed)
from datetime import datetime
from itertools import cycle
from logging import LogRecord
from multiprocessing import cpu_count
from queue import Queue
from typing import (Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple,
                    Union)
from urllib.parse import urlparse
import nmap
import psutil
from colorama import Fore, Style, init
from dask.distributed import Client, LocalCluster
from distributed.comm.core import CommClosedError
from halo import Halo  # type: ignore

nm_lock = threading.Lock()

log_queue: "Queue[logging.LogRecord]" = Queue(-1)

class SelectorsFilter(logging.Filter):
    def filter(self, record: LogRecord) -> bool:
        return not record.getMessage().startswith("Using selector:")

detailed_format_str = "%(asctime)s [%(levelname)s] %(name)s [%(threadName)s] %(funcName)s: %(message)s"
detailed_formatter = logging.Formatter(detailed_format_str)

LOGGING_CONFIG: Dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(message)s"
        },
        "detailed": {
            "format": detailed_format_str
        },
    },
    "handlers": {
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
        "queue_file": {
            "class": "logging.handlers.QueueHandler",
            "handlers": ["file_rotating"]
        },
        "file_rotating": {
            "level": "DEBUG",
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "detailed",
            "filename": os.path.join("STAYCALM_SCAN_LOGS", "staycalmscan.log"),
            "maxBytes": 5242880,
            "backupCount": 5,
            "encoding": "utf-8",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console", "queue_file"],
            "level": "DEBUG",
            "propagate": True,
        },
        "selectors": {
            "handlers": ["console", "queue_file"],
            "level": "INFO",
            "filters": ["selectors_filter"],
        },
    },
    "filters": {
        "selectors_filter": {
            "()": SelectorsFilter
        }
    },
}

os.makedirs("STAYCALM_SCAN_LOGS", exist_ok=True)
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

file_rotating_handler = logging.handlers.RotatingFileHandler(
    filename=os.path.join("STAYCALM_SCAN_LOGS", "staycalmscan.log"),
    maxBytes=5242880,
    backupCount=5,
    encoding="utf-8"
)
file_rotating_handler.setFormatter(detailed_formatter)
file_rotating_handler.setLevel(logging.DEBUG)

queue_listener = logging.handlers.QueueListener(
    log_queue,
    file_rotating_handler
)
queue_listener.start()

def shutdown_logging() -> None:
    queue_listener.stop()

atexit.register(shutdown_logging)

def strip_ansi_codes(text: str) -> str:
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)

def log(level: str, message: str, console: bool = True) -> None:
    stripped_message = strip_ansi_codes(message)
    if console:
        print(message)
    logger.log(getattr(logging, level.upper(), logging.INFO), stripped_message)

class DirectoryManager:
    @staticmethod
    def get_desktop_path() -> str:
        if platform.system() == "Windows":
            try:
                import winreg as reg
                key = reg.OpenKey(
                    reg.HKEY_CURRENT_USER,
                    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                )
                desktop_path, _ = reg.QueryValueEx(key, "Desktop")
                desktop_path = os.path.expandvars(desktop_path)
                return desktop_path
            except Exception as e:
                logger.error(f"Error retrieving Desktop path from registry: {e}")
                return os.path.join(os.path.expanduser("~"), "Desktop")
        else:
            return os.path.join(os.path.expanduser("~"), "Desktop")

    @staticmethod
    def create_directories() -> Tuple[str, str, str, str]:
        desktop_dir = DirectoryManager.get_desktop_path()
        base_dir = os.path.join(desktop_dir, "LEVERAGE")
        sub_dirs = ["XML", "TXT", "JSON", "STAYCALM_SCAN_LOGS"]
        dir_paths = [os.path.join(base_dir, sub_dir) for sub_dir in sub_dirs]
        for path in dir_paths:
            os.makedirs(path, exist_ok=True)
        return dir_paths[0], dir_paths[1], dir_paths[2], dir_paths[3]

class LoggerSetup:
    @staticmethod
    def create_log_file(log_dir: str) -> str:
        current_date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(log_dir, f"staycalmscan_log_{current_date}.log")
        if not os.path.exists(log_file):
            with open(log_file, "a", encoding="utf-8") as lf:
                lf.write(f"Log file created on {current_date}\n")
        return log_file

    @staticmethod
    def setup_logger(log_file: str) -> logging.Logger:
        new_logger = logging.getLogger(__name__)
        new_logger.setLevel(logging.DEBUG)
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler(log_file, encoding="utf-8")
        c_handler.setLevel(logging.DEBUG)
        f_handler.setLevel(logging.DEBUG)
        c_format = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        f_format = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        c_handler.setFormatter(c_format)
        f_handler.setFormatter(f_format)
        new_logger.addHandler(c_handler)
        new_logger.addHandler(f_handler)
        return new_logger

class ModuleInstaller:
    @staticmethod
    def dynamic_worker_count() -> int:
        total_memory = psutil.virtual_memory().total
        memory_factor = total_memory // (512 * 1024 * 1024)
        cpu_count = psutil.cpu_count() or 1
        cpu_factor = cpu_count * 3
        return min(memory_factor, cpu_factor, 61)

    @staticmethod
    def is_tool_installed(tool_name: str) -> bool:
        try:
            return shutil.which(tool_name) is not None
        except Exception:
            return False

    @staticmethod
    def install_system_dependencies_once():
        required_tools = ["pip", "nmap"]
        if getattr(ModuleInstaller, '_dependencies_checked', False):
            return
        setattr(ModuleInstaller, '_dependencies_checked', True)
        try:
            for tool in required_tools:
                if not ModuleInstaller.is_tool_installed(tool):
                    if platform.system() == "Windows":
                        process = subprocess.run(
                            [
                                "powershell.exe",
                                "-Command",
                                "$ProgressPreference = 'SilentlyContinue';",
                                "Start-Process",
                                "winget",
                                f"-ArgumentList 'install {tool} --silent --accept-package-agreements --accept-source-agreements'",
                                "-Wait",
                                "-NoNewWindow"
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=300
                        )
                        if process.returncode != 0:
                            sys.exit(1)
                    else:
                        process = subprocess.run(
                            [
                                "sudo", "apt-get", "install", "-yq", tool
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'),
                            timeout=300
                        )
                        if process.returncode != 0:
                            sys.exit(1)
        except subprocess.TimeoutExpired:
            sys.exit(1)
        except Exception:
            sys.exit(1)

    @staticmethod
    async def install_module(module_name: str) -> None:
        try:
            importlib.import_module(module_name.split('[')[0])
        except ImportError:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", module_name, "--quiet", "--disable-pip-version-check", "--no-cache-dir"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    @staticmethod
    async def install_modules(modules: Sequence[str]) -> None:
        tasks = [ModuleInstaller.install_module(module) for module in modules]
        await asyncio.gather(*tasks)

    @staticmethod
    def extract_modules_from_script(file_path: str) -> Sequence[str]:
        imported_modules: Set[str] = set()
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                tree: ast.Module = ast.parse(file.read(), filename=file_path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imported_modules.add(alias.name)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported_modules.add(node.module)
        except (IndentationError, SyntaxError):
            pass
        return list(imported_modules)

    @staticmethod
    def install_modules_from_script(file_path: str):
        ModuleInstaller.install_system_dependencies_once()
        modules = ModuleInstaller.extract_modules_from_script(file_path)
        asyncio.run(ModuleInstaller.install_modules(modules))

class Scanners:
    def __init__(self, target: str, target_type: str, logger: logging.Logger):
        self.target = target
        self.target_type = target_type
        self.logger = logger
        self.nm = self.initialize_nmap()

    @staticmethod
    def initialize_nmap() -> nmap.PortScanner:
        try:
            nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            log("ERROR", f"Nmap not found. Error: {e}", console=False)
            sys.exit(1)
        except Exception as e:
            log("ERROR", f"Unexpected error: {e}", console=False)
            sys.exit(1)
        return nm

    def dynamic_worker_count(self) -> int:
        total_memory = psutil.virtual_memory().total
        memory_factor = total_memory // (512 * 1024 * 1024)
        cpu_count = psutil.cpu_count() or 1
        cpu_factor = cpu_count * 3
        return min(memory_factor, cpu_factor, 61)

    def is_private_ip(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def is_command_available(self, command: str) -> bool:
        return shutil.which(command) is not None

    def run_command(
        self,
        command: List[str],
        scanner_name: str,
        timeout: Optional[int] = None,
        # ADDED: Allow override max workers to improve concurrency if needed
        max_workers_override: Optional[int] = None
    ) -> Optional[str]:
        if "powershell.exe" in command:
            command.insert(2, "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop';")

        spinner_text = f"Running {scanner_name} on {self.target}"
        spinner: Halo = Halo(text=spinner_text, spinner="dots")
        spinner.start()  # type: ignore
        colors: List[str] = [
            Fore.RED, Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.CYAN,
            Fore.MAGENTA, Fore.WHITE, Fore.LIGHTBLACK_EX, Fore.LIGHTBLUE_EX,
            Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTMAGENTA_EX,
            Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTYELLOW_EX,
        ]
        color_cycle: Any = itertools.cycle(colors)
        stop_event = threading.Event()

        def update_spinner_text() -> None:
            while not stop_event.is_set():
                color: str = next(color_cycle)
                spinner.text = f"{color}{Style.BRIGHT}Running {scanner_name} on {self.target}{Style.RESET_ALL}"
                time.sleep(0.1)

        threading.Thread(target=update_spinner_text, daemon=True).start()

        workers = max_workers_override if max_workers_override is not None else self.dynamic_worker_count()

        try:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                future = executor.submit(
                    subprocess.run,
                    command,
                    text=True,
                    timeout=timeout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
                )
                result = future.result()

            stop_event.set()
            spinner.stop()

            if result.returncode == 0:
                output = result.stdout.strip()
                unwanted_substrings: List[str] = [
                    "No pending reboots detected.",
                    "A system reboot is pending.",
                    "Python:",
                    "pip:",
                    "Chocolatey:",
                    "Ruby:",
                    "Git:",
                    "GitHub CLI:",
                    "AWS CLI:",
                    "AWS-Vault:",
                    "Docker:",
                    "Terraform:",
                    "JDK:",
                    "Node.js:",
                    "npm:",
                    "Permanent",
                    "Stale",
                    "Redacted",
                    "WHOIS DISCLAIMER",
                    "whois disclaimer",
                    "Whois disclaimer",
                    "NOTICE:",
                    "Notice:",
                    "notice:",
                    "TERMS OF USE:",
                    "terms of use",
                    "FinWait2",
                    "FOR LEGAL PURPOSES",
                    "for legal purposes",
                    "By using this service",
                    "Please note:",
                    "Please be aware:",
                    "The data in this record",
                    "does not guarantee",
                    "You agree that you may use this data only",
                    "The compilation, repackaging, dissemination",
                    "This service is intended only",
                    "It is explicitly forbidden",
                    "The provider does not guarantee",
                    "The Registrar does not",
                    "Without the prior written consent",
                    "By submitting a query",
                    "except as reasonably necessary",
                    "You may not use this data",
                    "Data completeness not guaranteed",
                    "REDACTED FOR PRIVACY"
                ]
                filtered_lines: List[str] = []
                for line in output.splitlines():
                    if not any(us in line for us in unwanted_substrings):
                        filtered_lines.append(line)

                output = "\n".join(filtered_lines)
                if output:
                    return output
                else:
                    self.logger.warning(f"No output from {scanner_name} on target {self.target}.")
                    return None
            else:
                self.logger.error(f"Error running {scanner_name}: {result.stderr.strip()}")
                return None
        except subprocess.TimeoutExpired:
            stop_event.set()
            spinner.stop()
            self.logger.error(f"Error: {scanner_name} timed out.")
            return None
        except Exception as e:
            stop_event.set()
            spinner.stop()
            self.logger.error(f"Error running {scanner_name}: {e}")
            return None

    def scan_port(
        self, ip: str, port: int, proto: str
    ) -> Tuple[int, Dict[str, Union[str, List[str], Mapping[str, str]]]]:
        arguments = (
            "-sS -T3 "
            "--min-hostgroup 32 --max-hostgroup 64 "
            "--min-parallelism 10 --max-parallelism 100 "
            "--max-rtt-timeout 100ms "
            "-sV -A -O --version-intensity 9 --script=default,vuln,banner,"
            "http-headers,http-title,vulners,dns-recursion,dns-srv-enum,dns-brute,"
            "broadcast-dns-service-discovery -PE -PP -PM -PS21,23,80,3389 -PA80,443,"
            "8080 --data-length 10 -vvv "
            "--defeat-rst-ratelimit"
        )
        self.logger.debug(f"Starting scanning on {ip}:{port}/{proto} with arguments: {arguments}")
        try:
            with nm_lock:
                self.nm.scan(
                    hosts=ip,
                    ports=str(port),
                    arguments=arguments,
                    sudo=True if proto == "udp" else False,
                )
        except nmap.PortScannerError as e:
            log("ERROR", f"Error occurred while scanning port {port} on IP {ip}: {e}", console=False)
            return port, {}
        except Exception as e:
            log("ERROR", f"Unexpected error occurred while scanning port {port} on IP {ip}: {e}", console=False)
            return port, {}

        scan_info: Dict[str, Union[str, List[str], Mapping[str, str]]] = self.nm[ip].get(proto, {}).get(port, {})
        self.logger.debug(f"Scanning Completed On {ip}:{port}/{proto}, result: {scan_info}")
        return port, scan_info

    def quick_scan(self, ip: str) -> Dict[str, List[int]]:
        arguments = (
            "-sS -T3 "
            "--min-hostgroup 32 --max-hostgroup 64 "
            "--min-parallelism 10 --max-parallelism 100 "
            "--max-rtt-timeout 100ms "
            "-O --version-intensity 9 --open -PE -PP -PM -PS21,23,80,3389 "
            "-PA80,443,8080 --data-length 10 -vvv "
            "--defeat-rst-ratelimit"
        )
        total_ports: int = 65535
        completed: Dict[str, int] = {"count": 0, "total": total_ports}
        open_ports: Dict[str, List[int]] = {"tcp": [], "udp": []}
        current_port: Dict[str, Optional[int]] = {"port": None}

        spinner_text = "STAY CALM"
        spinner: Halo = Halo(text=spinner_text, spinner="dots")
        spinner.start()  # type: ignore
        colors: List[str] = [
            Fore.RED, Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.CYAN,
            Fore.MAGENTA, Fore.BLACK, Fore.WHITE, Fore.LIGHTBLACK_EX,
            Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX,
            Fore.LIGHTMAGENTA_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX,
            Fore.LIGHTYELLOW_EX,
        ]
        color_cycle: Any = itertools.cycle(colors)
        stop_event = threading.Event()

        def update_spinner_text() -> None:
            while not stop_event.is_set():
                color: str = next(color_cycle)
                percentage: float = (completed["count"] / completed["total"]) * 100
                spinner.text = (
                    f"{color}{Style.BRIGHT}STAY CALM{Style.RESET_ALL} "
                    f"{Fore.GREEN}{Style.BRIGHT}[{Fore.WHITE}{Style.BRIGHT}Port{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{current_port['port']}{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}] "
                    f"{Fore.GREEN}{Style.BRIGHT}[{Fore.MAGENTA}{Style.BRIGHT}SCANNED{Style.RESET_ALL}"
                    f"{Fore.CYAN}{Style.BRIGHT}:{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}"
                    f"{completed['count']}{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}/{Style.RESET_ALL}"
                    f"{completed['total']}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT} "
                    f"{Fore.YELLOW}{Style.BRIGHT}PROGRESS{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}"
                    f"{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{percentage:.2f}{Fore.RED}{Style.BRIGHT}%{Style.RESET_ALL}"
                    f"{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}]"
                )
                time.sleep(0.1)

        threading.Thread(target=update_spinner_text, daemon=True).start()

        try:
            self.nm.scan(hosts=ip, arguments=arguments)
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        current_port["port"] = port
                        state: str = self.nm[host][proto][port]["state"]
                        if state == "open":
                            open_ports[proto].append(port)
        except nmap.PortScannerError as e:
            log("ERROR", f"Error occurred during quick scan on IP {ip}: {e}", console=False)
            stop_event.set()
            spinner.stop()
            return open_ports
        except Exception as e:
            log("ERROR", f"Unexpected error occurred during quick scan on IP {ip}: {e}", console=False)
            stop_event.set()
            spinner.stop()
            return open_ports

        stop_event.set()
        spinner.stop()
        return open_ports

    def run_advanced_ping(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop';",
                f"Test-Connection -ComputerName {self.target} -Count 5 -BufferSize 64 -TTL 128 -ErrorAction SilentlyContinue | Format-List"
            ]
            return self.run_command(command, "Advanced Ping Check")
        else:
            self.logger.error("Advanced Ping Check is only available on Windows.")
            return None

    def run_mtr(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop';",
                f"Test-NetConnection -TraceRoute -ComputerName {self.target} | Format-List"
            ]
            return self.run_command(command, "Advanced Traceroute")
        else:
            self.logger.error("Advanced Traceroute is only available on Windows.")
            return None

    def run_dig(self) -> Optional[str]:
        if platform.system() == "Windows":
            if self.is_private_ip(self.target):
                return None
            command = [
                "powershell.exe",
                "-Command",
                f"Resolve-DnsName -Name {self.target} -Type ANY -DnsOnly -ErrorAction SilentlyContinue | Format-List"
            ]
            return self.run_command(command, "Advanced DNS Lookup")
        else:
            self.logger.error("Advanced DNS Lookup is only available on Windows.")
            return None

    def run_advanced_whois(self) -> Optional[str]:
        if self.is_private_ip(self.target):
            return None
        if not self.is_command_available("whois"):
            self.logger.error("whois command is not installed.")
            return None
        command = ["whois", "-v", self.target]
        return self.run_command(command, "Advanced WHOIS")

    def run_advanced_network_diagnostics(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                (
                    "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'; "
                    "Get-NetAdapter | Format-List; "
                    "Get-NetIPAddress | Format-List; "
                    "Get-NetRoute | Format-List; "
                    "Get-NetNeighbor | Format-List; "
                    "Get-NetTCPConnection | Format-List; "
                    f"Test-NetConnection -ComputerName {self.target} -Port 80 -InformationLevel Detailed | Format-List"
                )
            ]
            return self.run_command(command, "Advanced Network Diagnostics")
        else:
            self.logger.error("Advanced Network Diagnostics is only available on Windows.")
            return None

    def run_advanced_curl(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                (
                    "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'; "
                    f"Invoke-WebRequest -Uri 'http://{self.target}' -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 30 -Verbose"
                )
            ]
            return self.run_command(command, "Advanced Web Request")
        else:
            command = ["curl", "-v", "-L", "-k", f"http://{self.target}"]
            return self.run_command(command, "Advanced Curl Request")

    def run_advanced_openssl_scan(self) -> Optional[str]:
        if not self.is_command_available("openssl"):
            self.logger.error("OpenSSL is not installed.")
            return None
        command = [
            "openssl",
            "s_client",
            "-connect",
            f"{self.target}:443",
            "-servername",
            self.target,
            "-tls1_2",
            "-cipher", "ALL",
            "-showcerts",
            "-status",
            "-alpn", "http/1.1"
        ]
        return self.run_command(command, "Advanced OpenSSL Scan")

    def run_nikto_scan(self) -> Optional[str]:
        if not self.is_command_available("nikto"):
            self.logger.error("Nikto is not installed.")
            return None
        command = [
            "nikto",
            "-host", self.target,
            "-port", "80,443",
            "-Format", "txt",
            "-output", f"nikto_{self.target}.txt"
        ]
        return self.run_command(command, "Nikto Web Server Scan")

    def run_sslscan(self) -> Optional[str]:
        if not self.is_command_available("sslscan"):
            self.logger.error("SSLScan is not installed.")
            return None
        command = [
            "sslscan",
            "--no-failed",
            self.target
        ]
        return self.run_command(command, "SSLScan")

    def run_service_specific_nmap(self, port: int, service_name: str) -> Optional[str]:
        if not self.is_command_available("nmap"):
            self.logger.error("Nmap is not installed.")
            return None
        scripts = {
            "http": "http-enum,http-vuln*,http-headers,http-title,http-methods",
            "ftp": "ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor",
            "ssh": "ssh-auth-methods,ssh-hostkey,sshv1",
            "smtp": "smtp-enum-users,smtp-open-relay,smtp-commands",
        }
        script = scripts.get(service_name, "default")

        command = [
            "nmap",
            "-sV",
            "--min-hostgroup", "32",
            "--max-hostgroup", "64",
            "--min-parallelism", "10",
            "--max-parallelism", "100",
            "--max-rtt-timeout", "100ms",
            "--defeat-rst-ratelimit",
            "--defeat-icmp-ratelimit",
            "--script", script,
            "-p", str(port),
            self.target
        ]
        return self.run_command(command, f"Nmap {service_name.upper()} Script")

    def run_ping_check(self) -> Optional[str]:
        command = (
            ["ping", "-n", "1", self.target]
            if platform.system() == "Windows"
            else ["ping", "-c", "1", self.target]
        )
        return self.run_command(command, "Ping Check")

    def run_traceroute(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = ["tracert", "-4", "-d", "-h", "30", self.target]
        else:
            command = ["traceroute", "-4", "-n", "-m", "30", self.target]
        return self.run_command(command, "Traceroute")

    def run_nslookup(self) -> Optional[str]:
        command = ["nslookup", self.target]
        return self.run_command(command, "NSLookup")

    def run_whois(self) -> Optional[str]:
        if self.is_private_ip(self.target):
            return None
        if not self.is_command_available("whois"):
            self.logger.error("whois command is not installed.")
            return None
        command = ["whois", self.target]
        return self.run_command(command, "WHOIS")

    def run_test_net_connection(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                f"Test-NetConnection -ComputerName {self.target} -Port 80 | Format-List"
            ]
            return self.run_command(command, "Test-NetConnection")
        else:
            return None

    def run_resolve_dns_name(self) -> Optional[str]:
        if platform.system() == "Windows":
            if self.is_private_ip(self.target):
                return None
            command = [
                "powershell.exe",
                "-Command",
                f"Resolve-DnsName -Name {self.target} -Type A | Format-List"
            ]
            return self.run_command(command, "Resolve-DnsName")
        else:
            return None

    def run_test_connection(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                f"Test-Connection -Count 1 {self.target} | Format-List"
            ]
            return self.run_command(command, "Test-Connection")
        else:
            return None

    def run_get_net_tcp_connection(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                "Get-NetTCPConnection | Format-Table"
            ]
            return self.run_command(command, "Get-NetTCPConnection")
        else:
            return None

    def run_get_net_adapter(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                "Get-NetAdapter | Format-Table"
            ]
            return self.run_command(command, "Get-NetAdapter")
        else:
            return None

    def run_get_net_ip_configuration(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                "Get-NetIPConfiguration | Format-Table"
            ]
            return self.run_command(command, "Get-NetIPConfiguration")
        else:
            return None

    def run_get_net_route(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                "Get-NetRoute | Format-Table"
            ]
            return self.run_command(command, "Get-NetRoute")
        else:
            return None

    def run_get_net_neighbor(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                "Get-NetNeighbor | Format-Table"
            ]
            return self.run_command(command, "Get-NetNeighbor")
        else:
            return None

    def run_invoke_web_request(self) -> Optional[str]:
        if platform.system() == "Windows":
            command = [
                "powershell.exe",
                "-Command",
                f"Invoke-WebRequest -Uri 'http://{self.target}' -UseBasicParsing | Format-List"
            ]
            return self.run_command(command, "Invoke-WebRequest")
        else:
            return None

    def run_curl(self) -> Optional[str]:
        command = ["curl", "-v", "-L", "-k", f"http://{self.target}"]
        return self.run_command(command, "Curl")

    def run_openssl_scan(self) -> Optional[str]:
        if not self.is_command_available("openssl"):
            self.logger.error("OpenSSL is not installed.")
            return None
        command = [
            "openssl",
            "s_client",
            "-connect",
            f"{self.target}:443",
            "-servername",
            self.target,
            "-showcerts",
            "-status"
        ]
        return self.run_command(command, "OpenSSL Scan")

    def run_advanced_nslookup(self) -> Optional[str]:
        command = ["nslookup", "-type=any", self.target]
        return self.run_command(command, "Advanced NSLookup")

class ReportGenerator:
    def __init__(
        self,
        xml_dir: str,
        txt_dir: str,
        json_dir: str,
        logger: logging.Logger,
    ):
        self.xml_dir = xml_dir
        self.txt_dir = txt_dir
        self.json_dir = json_dir
        self.logger = logger

    def save_reports(
        self,
        detailed_results: Mapping[
            str,
            Mapping[int, Mapping[str, Union[str, List[str], Mapping[str, str]]]],
        ],
        scanner_results: Dict[str, Optional[str]],
        tag: str,
    ):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        xml_path = os.path.join(
            self.xml_dir, f"scan_xml_report_{tag}_{timestamp}.xml"
        )
        report_filename = os.path.join(
            self.txt_dir, f"scan_txt_report_{tag}_{timestamp}.txt"
        )
        results_json_path = os.path.join(
            self.json_dir, f"scan_json_report_{tag}_{timestamp}.json"
        )

        detailed_xml_dir = os.path.join(self.xml_dir, "detailed")
        detailed_txt_dir = os.path.join(self.txt_dir, "detailed")
        detailed_json_dir = os.path.join(self.json_dir, "detailed")

        os.makedirs(detailed_xml_dir, exist_ok=True)
        os.makedirs(detailed_txt_dir, exist_ok=True)
        os.makedirs(detailed_json_dir, exist_ok=True)

        start_time = time.time()

        spinner_text = f"Saving Reports for tag {tag}"
        spinner: Halo = Halo(text=spinner_text, spinner="dots")
        spinner.start()  # type: ignore
        colors: List[str] = [
            Fore.RED,
            Fore.GREEN,
            Fore.BLUE,
            Fore.YELLOW,
            Fore.CYAN,
            Fore.MAGENTA,
            Fore.BLACK,
            Fore.WHITE,
            Fore.LIGHTBLACK_EX,
            Fore.LIGHTBLUE_EX,
            Fore.LIGHTCYAN_EX,
            Fore.LIGHTGREEN_EX,
            Fore.LIGHTMAGENTA_EX,
            Fore.LIGHTRED_EX,
            Fore.LIGHTWHITE_EX,
            Fore.LIGHTYELLOW_EX,
        ]
        color_cycle: Any = itertools.cycle(colors)
        stop_event = threading.Event()

        def update_spinner_text() -> None:
            while not stop_event.is_set():
                color: str = next(color_cycle)
                spinner.text = f"{color}{Style.BRIGHT}Saving Reports for tag {tag}{Style.RESET_ALL}"
                time.sleep(0.1)

        threading.Thread(target=update_spinner_text, daemon=True).start()

        with ThreadPoolExecutor(
            max_workers=ModuleInstaller.dynamic_worker_count()
        ) as executor:
            futures = [
                executor.submit(
                    self.save_xml_report, detailed_results, scanner_results, xml_path, detailed_xml_dir
                ),
                executor.submit(
                    self.save_text_report,
                    detailed_results,
                    scanner_results,
                    report_filename,
                    detailed_txt_dir,
                ),
                executor.submit(
                    self.save_json_report,
                    detailed_results,
                    scanner_results,
                    results_json_path,
                    detailed_json_dir,
                ),
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                    log(
                        "INFO",
                        f"{Fore.GREEN}{Style.BRIGHT}Report saved successfully.{Style.RESET_ALL}",
                        console=False,
                    )
                except Exception as e:
                    log(
                        "ERROR",
                        f"{Fore.RED}{Style.BRIGHT}Error occurred while saving report: {e}{Style.RESET_ALL}",
                        console=True,
                    )

        stop_event.set()
        spinner.stop()

        elapsed_time = time.time() - start_time
        hours = int(elapsed_time // 3600)
        minutes = int((elapsed_time % 3600) // 60)
        seconds = int(elapsed_time % 60)

        total_ports = sum(len(ports) for ports in detailed_results.values())
        log(
            "INFO",
            f"{Fore.RED}{Style.BRIGHT}TOTAL OPEN PORTS SCANNED{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{total_ports}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}",
            console=True,
        )
        log(
            "INFO",
            f"{Fore.WHITE}{Style.BRIGHT}Report generation completed in{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT} {hours:02d}:{minutes:02d}:{seconds:02d}.{Style.RESET_ALL}",
            console=False,
        )

    def save_xml_report(
        self,
        detailed_results: Mapping[
            str,
            Mapping[int, Mapping[str, Union[str, List[str], Mapping[str, str]]]],
        ],
        scanner_results: Dict[str, Optional[str]],
        xml_path: str,
        detailed_dir: str,
    ):
        try:
            os.makedirs(os.path.dirname(xml_path), exist_ok=True)
            root = ET.Element("ScanResults")

            for ip, ports_info in detailed_results.items():
                ip_elem = ET.SubElement(root, "IP")
                ip_elem.set("address", ip)
                for port, info in ports_info.items():
                    port_elem = ET.SubElement(ip_elem, "Port")
                    port_elem.set("id", str(port))
                    filtered_info = {
                        k: v for k, v in info.items() if v and v not in ["Not available", "None"]
                    }

                    vulnerability_found = False
                    vulnerability_details: List[str] = []

                    for key, value in filtered_info.items():
                        if isinstance(value, dict):
                            for subkey, subvalue in value.items():
                                if subvalue and subvalue not in ["Not available", "None"]:
                                    if (
                                        "vuln" in subkey.lower()
                                        or "cve" in subkey.lower()
                                        or "exploit" in subkey.lower()
                                    ):
                                        vulnerability_found = True
                                        vulnerability_details.append(
                                            f"{key + subkey.replace('_', '').capitalize()}: {strip_ansi_codes(str(subvalue))}"
                                        )
                                    else:
                                        sub_elem = ET.SubElement(
                                            port_elem, key + subkey.replace("_", "").capitalize()
                                        )
                                        sub_elem.text = strip_ansi_codes(str(subvalue))
                                    self.save_detailed_file(
                                        detailed_dir, f"{key}_{subkey}", subvalue, "xml"
                                    )
                        elif isinstance(value, list):
                            for item in value:
                                if (
                                    "vuln" in str(item).lower()
                                    or "cve" in str(item).lower()
                                    or "exploit" in str(item).lower()
                                ):
                                    vulnerability_found = True
                                    vulnerability_details.append(
                                        f"{key.replace('_', '').capitalize()}: {strip_ansi_codes(str(item))}"
                                    )
                                else:
                                    list_elem = ET.SubElement(
                                        port_elem, key.replace("_", "").capitalize()
                                    )
                                    list_elem.text = strip_ansi_codes(str(item))
                                self.save_detailed_file(detailed_dir, key, item, "xml")
                        else:
                            if (
                                "vuln" in str(value).lower()
                                or "cve" in str(value).lower()
                                or "exploit" in str(value).lower()
                            ):
                                vulnerability_found = True
                                vulnerability_details.append(
                                    f"{key.replace('_', '').capitalize()}: {strip_ansi_codes(str(value))}"
                                )
                            else:
                                info_elem = ET.SubElement(
                                    port_elem, key.replace("_", "").capitalize()
                                )
                                info_elem.text = strip_ansi_codes(str(value))
                            self.save_detailed_file(detailed_dir, key, value, "xml")

                    if vulnerability_found:
                        warning_elem = ET.SubElement(port_elem, "Warning")
                        warning_elem.text = (
                            "[[-WARNING-]] !POSSIBLE! VULNs ~OR~ CVEs !DETECTED! [[-WARNING-]]"
                        )
                        for detail in vulnerability_details:
                            tag, detail_text = detail.split(": ", 1)
                            detail_elem = ET.SubElement(port_elem, tag)
                            detail_elem.text = detail_text

            for scanner_name, output in scanner_results.items():
                if output:
                    scanner_elem = ET.SubElement(root, "ScannerResult")
                    scanner_elem.set("name", scanner_name)
                    scanner_elem.text = output

            tree = ET.ElementTree(root)
            tree.write(xml_path, encoding="utf-8", xml_declaration=True)
            log(
                "INFO",
                f"\n{Fore.CYAN}{Style.BRIGHT}Detailed XML Report Saved To{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.BLUE}{Style.BRIGHT}{xml_path}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}\n",
                console=True,
            )
        except Exception as e:
            log(
                "ERROR",
                f"{Fore.RED}{Style.BRIGHT}Error occurred while saving the detailed XML report: {e}{Style.RESET_ALL}\n",
                console=True,
            )

    def save_json_report(
        self,
        detailed_results: Mapping[
            str,
            Mapping[int, Mapping[str, Union[str, List[str], Mapping[str, str]]]],
        ],
        scanner_results: Dict[str, Optional[str]],
        results_json_path: str,
        detailed_dir: str,
    ):
        try:
            os.makedirs(os.path.dirname(results_json_path), exist_ok=True)
            organized_results: Dict[
                str, List[Dict[str, Union[str, List[str], Mapping[str, str]]]]
            ] = {}

            for ip, ports_info in detailed_results.items():
                if ip not in organized_results:
                    organized_results[ip] = []
                for port, info in ports_info.items():
                    port_info: Dict[str, Union[str, List[str], Mapping[str, str]]] = {
                        "Port": str(port)
                    }
                    filtered_info = {k: v for k, v in info.items() if v}

                    warning_inserted = False
                    for key, value in filtered_info.items():
                        if isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_value and sub_value not in ["Not available", "None"]:
                                    if ("vuln" in sub_key.lower() or "cve" in sub_key.lower() or "exploit" in sub_key.lower()) and not warning_inserted:
                                        warning = (
                                            "[[-WARNING-]] !POSSIBLE! VULNs ~OR~ CVEs !DETECTED! [[-WARNING-]]"
                                        )
                                        port_info[f"Warning_{key}_{sub_key}"] = warning
                                        warning_inserted = True
                                    port_info[f"{key}_{sub_key}"] = strip_ansi_codes(str(sub_value))
                                    self.save_detailed_file(
                                        detailed_dir, f"{key}_{sub_key}", sub_value, "json"
                                    )
                        elif isinstance(value, list):
                            processed_list: List[str] = []
                            for item in value:
                                if ("vuln" in item.lower() or "cve" in item.lower() or "exploit" in item.lower()) and not warning_inserted:
                                    warning = (
                                        "[[-WARNING-]] !POSSIBLE! VULNs ~OR~ CVEs !DETECTED! [[-WARNING-]]"
                                    )
                                    port_info[f"Warning_{key}"] = warning
                                    warning_inserted = True
                                processed_list.append(strip_ansi_codes(str(item)))
                                self.save_detailed_file(detailed_dir, key, item, "json")
                            port_info[key] = processed_list
                        else:
                            if ("vuln" in str(value).lower() or "cve" in str(value).lower() or "exploit" in str(value).lower()) and not warning_inserted:
                                warning = (
                                    "[[-WARNING-]] !POSSIBLE! VULNs ~OR~ CVEs !DETECTED! [[-WARNING-]]"
                                )
                                port_info[f"Warning_{key}"] = warning
                                warning_inserted = True
                            port_info[key] = strip_ansi_codes(str(value))
                            self.save_detailed_file(detailed_dir, key, value, "json")

                    organized_results[ip].append(port_info)

            for scanner_name, output in scanner_results.items():
                if output:
                    organized_results[scanner_name] = [{"Result": output}]

            with open(results_json_path, "w", encoding="utf-8") as json_file:
                json.dump(organized_results, json_file, indent=4)
            log(
                "INFO",
                f"\n{Fore.CYAN}{Style.BRIGHT}Detailed JSON Report Saved To{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{results_json_path}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}\n",
                console=True,
            )
        except Exception as e:
            log(
                "ERROR",
                f"{Fore.RED}{Style.BRIGHT}An error occurred while saving the detailed report: {str(e)}{Style.RESET_ALL}\n",
                console=True,
            )

    def save_text_report(
        self,
        detailed_results: Mapping[
            str,
            Mapping[int, Mapping[str, Union[str, List[str], Mapping[str, str]]]],
        ],
        scanner_results: Dict[str, Optional[str]],
        report_filename: str,
        detailed_dir: str,
    ):
        try:
            os.makedirs(os.path.dirname(report_filename), exist_ok=True)
            with open(report_filename, "w", encoding="utf-8") as report_file:
                for ip, ports_info in detailed_results.items():
                    report_file.write(f"IP: {ip}\n")
                    for port, info in ports_info.items():
                        report_file.write(f"  Port {port}:\n")
                        processed_fields: Set[str] = set()
                        vulnerability_found = False
                        vulnerability_details: List[str] = []

                        for field, value in info.items():
                            if field not in processed_fields and value and value not in ["Not available", "None"]:
                                processed_fields.add(field)
                                if isinstance(value, dict):
                                    report_file.write(f"    {field.capitalize()}:\n")
                                    for sub_key, sub_value in value.items():
                                        if sub_value and sub_value not in ["Not available", "None"]:
                                            if ("vuln" in sub_key.lower() or "cve" in sub_key.lower() or "exploit" in sub_key.lower()):
                                                vulnerability_found = True
                                                vulnerability_details.append(
                                                    f"      {sub_key}: {strip_ansi_codes(str(sub_value))}\n"
                                                )
                                                self.save_detailed_file(
                                                    detailed_dir,
                                                    f"{field}_{sub_key}",
                                                    sub_value,
                                                    "txt",
                                                )
                                            else:
                                                report_file.write(
                                                    f"      {sub_key}: {strip_ansi_codes(str(sub_value))}\n"
                                                )
                                                self.save_detailed_file(
                                                    detailed_dir,
                                                    f"{field}_{sub_key}",
                                                    sub_value,
                                                    "txt",
                                                )
                                elif isinstance(value, list):
                                    report_file.write(f"    {field.capitalize()}:\n")
                                    for item in value:
                                        if ("vuln" in item.lower() or "cve" in item.lower() or "exploit" in item.lower()):
                                            vulnerability_found = True
                                            vulnerability_details.append(
                                                f"      {strip_ansi_codes(item)}\n"
                                            )
                                            self.save_detailed_file(
                                                detailed_dir, field, item, "txt"
                                            )
                                        else:
                                            report_file.write(
                                                f"      {strip_ansi_codes(item)}\n"
                                            )
                                            self.save_detailed_file(
                                                detailed_dir, field, item, "txt"
                                            )
                                else:
                                    if ("vuln" in str(value).lower() or "cve" in str(value).lower() or "exploit" in str(value).lower()):
                                        vulnerability_found = True
                                        vulnerability_details.append(
                                            f"    {field.capitalize()}: {strip_ansi_codes(str(value))}\n"
                                        )
                                        self.save_detailed_file(
                                            detailed_dir, field, value, "txt"
                                        )
                                    else:
                                        report_file.write(
                                            f"    {field.capitalize()}: {strip_ansi_codes(str(value))}\n"
                                        )
                                        self.save_detailed_file(
                                            detailed_dir, field, value, "txt"
                                        )
                        if vulnerability_found:
                            report_file.write(
                                "[[-WARNING-]] !POSSIBLE! VULNs ~OR~ CVEs !DETECTED! [[-WARNING-]]\n"
                            )
                            for detail in vulnerability_details:
                                report_file.write(detail)
                        report_file.write("\n")

                for scanner_name, output in scanner_results.items():
                    if output:
                        report_file.write(f"\n{scanner_name.upper()} RESULTS:\n")
                        report_file.write(f"{output}\n")

            log(
                "INFO",
                f"\n{Fore.CYAN}{Style.BRIGHT}Detailed TEXT Report Saved To{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.YELLOW}{Style.BRIGHT}{report_filename}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}\n",
                console=True,
            )
        except Exception as e:
            log(
                "ERROR",
                f"{Fore.RED}{Style.BRIGHT}Error occurred while saving the detailed TEXT report: {e}{Style.RESET_ALL}\n",
                console=True,
            )

    def save_detailed_file(
        self,
        detailed_dir: str,
        field: str,
        value: Union[str, List[str], Mapping[str, str]],
        file_format: str,
    ):
        os.makedirs(detailed_dir, exist_ok=True)
        if file_format == "txt":
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    self.save_detailed_file(
                        detailed_dir, f"{field}_{sub_key}", sub_value, file_format
                    )
            elif isinstance(value, list):
                with open(os.path.join(detailed_dir, f"{field}.txt"), "a", encoding="utf-8") as file:
                    for item in value:
                        file.write(f"{strip_ansi_codes(str(item))}\n")
            else:
                with open(os.path.join(detailed_dir, f"{field}.txt"), "a", encoding="utf-8") as file:
                    file.write(f"{strip_ansi_codes(str(value))}\n")
        elif file_format == "json":
            detailed_file_path = os.path.join(detailed_dir, f"{field}.json")
            if isinstance(value, dict):
                with open(detailed_file_path, "a", encoding="utf-8") as file:
                    json.dump(value, file, indent=4)
            elif isinstance(value, list):
                with open(detailed_file_path, "a", encoding="utf-8") as file:
                    json.dump(value, file, indent=4)
            else:
                with open(detailed_file_path, "a", encoding="utf-8") as file:
                    json.dump({field: value}, file, indent=4)
        elif file_format == "xml":
            detailed_file_path = os.path.join(detailed_dir, f"{field}.xml")
            root = ET.Element(field)
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    sub_elem = ET.SubElement(root, sub_key)
                    sub_elem.text = strip_ansi_codes(str(sub_value))
            elif isinstance(value, list):
                for item in value:
                    item_elem = ET.SubElement(root, field)
                    item_elem.text = strip_ansi_codes(str(item))
            else:
                root.text = strip_ansi_codes(str(value))
            tree = ET.ElementTree(root)
            tree.write(detailed_file_path, encoding="utf-8", xml_declaration=True)

class StayCalmScan:
    def __init__(self):
        init(autoreset=True)
        self.xml_dir, self.txt_dir, self.json_dir, self.log_dir = DirectoryManager.create_directories()
        self.data_dir = ""
        self.log_file = LoggerSetup.create_log_file(self.log_dir)
        self.logger = LoggerSetup.setup_logger(self.log_file)
        self.logger.setLevel(logging.WARNING)
        self.report_generator = ReportGenerator(self.xml_dir, self.txt_dir, self.json_dir, self.logger)

    def wait_for_user_input(self, stop_event: threading.Event) -> None:
        input(f"{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
        stop_event.set()

    def print_ascii_art(self) -> None:
        colors: List[str] = [
            Fore.RED, Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.CYAN,
            Fore.MAGENTA, Fore.BLACK, Fore.LIGHTBLACK_EX, Fore.LIGHTBLUE_EX,
            Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTMAGENTA_EX,
            Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTYELLOW_EX,
        ]
        color_cycle: Any = itertools.cycle(colors)

        ascii_art_lines: List[str] = [
            Style.BRIGHT + Fore.RED + "              .                                                      .",
            Style.BRIGHT + Fore.RED + "            .n                   .                 .                  n.",
            Style.BRIGHT + Fore.RED + "      .   .dP                  dP                   9b                 9b.    .",
            Style.BRIGHT + Fore.RED + "     4    qXb         .       dX                     Xb       .        dXp     X",
            Style.BRIGHT + Fore.RED + "    dX.    9Xb      .dXb    _dXb.                    _dXb.    dXP       .Xb     .4 ",
            Style.BRIGHT + Fore.RED + "    9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP",
            Style.BRIGHT + Fore.RED + "     9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP",
            Style.BRIGHT + Fore.RED + "      9XXXXXXXXXXXXXXXXXXXXX'~   ~OOO8b   d8OOO'~   ~XXXXXXXXXXXXXXXXXXXXXP'",
            Style.BRIGHT + Fore.RED + "        9XXXXXXXXXXXP' 9XX'   ",
            Style.BRIGHT + Fore.RED + "            ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~",
            Style.BRIGHT + Fore.RED + "                            )b.  .dbo.dP'v'9b.odb.  .dX(",
            Style.BRIGHT + Fore.RED + "                          ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.",
            Style.BRIGHT + Fore.RED + "                         dXXXXXXXXXXXP'   .   9XXXXXXXXXXXb",
            Style.BRIGHT + Fore.RED + "                        dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb",
            Style.BRIGHT + Fore.RED + "                        9XXb'   XXXXXb.dX|Xb.dXXXXX'   dXXP",
            Style.BRIGHT + Fore.RED + "                         '      9XXXXXX(   )XXXXXXP      ' ",
            Style.BRIGHT + Fore.RED + "                                  XXXX X.v'.X XXXX",
            Style.BRIGHT + Fore.RED + "                                  XP^X'b   d'X^XX",
            Style.BRIGHT + Fore.RED + "                                  X. 9     '  P )X",
            Style.BRIGHT + Fore.RED + "                                  b         '  d'",
            Style.BRIGHT + Fore.RED + "                                                '",
            Fore.BLUE + "READ " + Fore.RED + ":" + Fore.WHITE + " This tool is for educational purposes only." + Style.RESET_ALL,
            Fore.BLUE + "DEV  " + Fore.RED + ":" + Fore.WHITE + " Dr4gnf1y / https://github.com/Dr4gnf1y" + Style.RESET_ALL,
            Fore.GREEN + "START HERE " + Fore.RED + ":" + Fore.YELLOW + " PRESS ENTER TO BEGIN USER INPUT"]

        stop_event = threading.Event()

        def update_flashing_text() -> None:
            while not stop_event.is_set():
                color: str = next(color_cycle)
                flashing_text = (
                    f"{Style.BRIGHT}{color}   STAY{Style.RESET_ALL}    "
                    f"{Style.BRIGHT}{Fore.RED}98v8P'{Style.RESET_ALL}  "
                    f"{Style.BRIGHT}{color}    CALM{Style.RESET_ALL}"
                )
                ascii_art_lines[8] = (
                    Style.BRIGHT + Fore.RED +
                    "        9XXXXXXXXXXXP' 9XX'   " + flashing_text + Style.BRIGHT + Fore.RED + "   XXP' 9XXXXXXXXXXXP'"
                )

                print("\033[H\033[J" + "\n".join(ascii_art_lines))
                time.sleep(0.05)

        flashing_thread = threading.Thread(target=update_flashing_text, daemon=True)
        flashing_thread.start()

        input_thread = threading.Thread(target=self.wait_for_user_input, args=(stop_event,))
        input_thread.start()

        input_thread.join()
        stop_event.set()
        flashing_thread.join()

    @staticmethod
    def format_ports(ports: List[int], per_line: int = 10) -> str:
        sorted_ports = sorted(ports)
        lines = [
            sorted_ports[i : i + per_line]
            for i in range(0, len(sorted_ports), per_line)
        ]
        formatted_lines = "\n".join(
            f"{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}"
            + f"{Fore.WHITE}{Style.BRIGHT}] [{Style.RESET_ALL}".join(
                f"{Fore.RED}{Style.BRIGHT}{port:>5}{Style.RESET_ALL}" for port in line
            )
            + f"{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}"
            for line in lines
        )
        return formatted_lines

    @staticmethod
    def dynamic_worker_count() -> int:
        total_memory = psutil.virtual_memory().total
        memory_factor = total_memory // (512 * 1024 * 1024)
        cpu_factor = cpu_count() * 15
        return min(memory_factor, cpu_factor, 61)

    @staticmethod
    def target_input_type(input_str: str) -> str:
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        domain_pattern = r'^(?:[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$'
        port_pattern = r'^\d{1,5}$'
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        url_pattern = r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[-\w._~:/?#[\]@!$&()*+,;=]*)?$'
        asn_pattern = r'^AS\d+$'
        if re.match(ip_pattern, input_str):
            return "ip"
        elif re.match(domain_pattern, input_str):
            return "domain"
        elif re.match(port_pattern, input_str):
            return "port"
        elif re.match(mac_pattern, input_str):
            return "mac"
        elif re.match(url_pattern, input_str):
            return "url"
        elif re.match(asn_pattern, input_str):
            return "asn"
        else:
            return "unknown"

    @staticmethod
    def extract_hostname(url: str) -> str:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname is None:
            raise ValueError(f"{Fore.RED}{Style.BRIGHT}Invalid URL: {url}{Style.RESET_ALL}")
        return hostname

    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        try:
            with ProcessPoolExecutor(max_workers=StayCalmScan.dynamic_worker_count()) as executor:
                future = executor.submit(socket.gethostbyname, hostname)
                ip = future.result()
            return ip
        except socket.gaierror:
            log("ERROR", f"{Fore.RED}{Style.BRIGHT}Failed to resolve hostname: {hostname}{Style.RESET_ALL}", console=True)
            return None
        except Exception as e:
            log("ERROR", f"{Fore.RED}{Style.BRIGHT}Unexpected error occurred while resolving hostname: {e}{Style.RESET_ALL}", console=True)
            return None

    @staticmethod
    def get_local_ip() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('10.255.255.255', 1))
                local_ip = s.getsockname()[0]
        except Exception as e:
            log("ERROR", f"{Fore.RED}{Style.BRIGHT}Failed to obtain local IP, defaulting to localhost: {e}{Style.RESET_ALL}")
            local_ip = '127.0.0.1'
        return local_ip

    def get_target(self) -> Tuple[str, str]:
        init(autoreset=True)
        while True:
            print(f"{Fore.RED}{Style.BRIGHT}Enter A Scan Type{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}\n{Fore.WHITE}1.{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}LOCAL{Style.RESET_ALL}\n{Fore.WHITE}2.{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}TARGET{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{Style.BRIGHT}Type Choice{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}({Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}1{Style.RESET_ALL} {Fore.BLACK}{Style.BRIGHT}or{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}2{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}){Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} ", end='')

            choice = input(f"{Fore.MAGENTA}{Style.BRIGHT}")
            while choice not in ("1", "2"):
                print(f"{Fore.RED}{Style.BRIGHT}Invalid choice{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} {Fore.YELLOW}{Style.BRIGHT}Please enter {Fore.GREEN}{Style.BRIGHT}({Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}1{Style.RESET_ALL} {Fore.BLACK}{Style.BRIGHT}or{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}2{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}){Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} ", end='')
                choice = input(f"{Fore.MAGENTA}{Style.BRIGHT}")
            if choice == "1":
                return self.get_local_ip(), "local"
            elif choice == "2":
                print(
                    f"{Fore.RED}Types Include:{Style.RESET_ALL}\n"
                    f"{Fore.WHITE}"
                    f"IP Address (e.g., 192.168.0.1),\n"
                    f"Domain (e.g., example.com),\n"
                    f"Port (e.g., 80),\n"
                    f"MAC (e.g., 00:1A:2B:3C:4D:5E),\n"
                    f"URL (e.g., https://example.com),\n"
                    f"ASN (e.g., AS12345){Style.RESET_ALL}"
                )
                target = input(f"{Fore.YELLOW}{Style.BRIGHT}Enter Target Type: {Style.RESET_ALL}{Fore.MAGENTA}{Style.BRIGHT}")
                target_type = self.target_input_type(target)

                if target_type == "unknown":
                    print(f"{Fore.RED}{Style.BRIGHT}Invalid input:{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}{target}{Style.RESET_ALL}")
                else:
                    if target_type == "url":
                        try:
                            hostname = self.extract_hostname(target)
                            target = hostname
                        except ValueError as e:
                            print(f"{Fore.RED}{Style.BRIGHT}{str(e)}{Style.RESET_ALL}")
                            continue
                    target = re.sub(r'^https?://', '', target)
                    target = target.rstrip('/')
                    spinner_text = ''.join([Fore.MAGENTA, Style.BRIGHT, 'Locating Target ', target, Style.RESET_ALL])
                    spinner: Halo = Halo(text=spinner_text, spinner="dots")
                    spinner.start()  # type: ignore
                    colors: List[str] = [
                        Fore.RED, Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.CYAN,
                        Fore.MAGENTA, Fore.WHITE, Fore.LIGHTBLACK_EX, Fore.LIGHTBLUE_EX,
                        Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTMAGENTA_EX,
                        Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTYELLOW_EX,
                    ]
                    color_cycle: Any = itertools.cycle(colors)
                    stop_event = threading.Event()

                    def update_spinner_text() -> None:
                        while not stop_event.is_set():
                            color: str = next(color_cycle)
                            spinner.text = (
                                f"{color}{Style.BRIGHT}Locating Target {Fore.WHITE}{target}{Style.RESET_ALL}"
                            )
                            time.sleep(0.1)

                    threading.Thread(target=update_spinner_text, daemon=True).start()

                    try:
                        with ProcessPoolExecutor(max_workers=self.dynamic_worker_count()) as executor:
                            future = executor.submit(subprocess.run, f"ping -c 1 {target}", shell=True, capture_output=True, text=True)
                            result = future.result()
                        spinner.stop()
                        if result.returncode == 0:
                            log("INFO", f"{Fore.GREEN}{Style.BRIGHT}Ping Check Succeeded{Style.RESET_ALL}{Fore.CYAN}{Style.BRIGHT}:{Style.RESET_ALL}{Fore.MAGENTA}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}{target}{Style.RESET_ALL}{Fore.MAGENTA}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}TARGET LOCKED{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}]{Style.RESET_ALL}", console=True)
                        else:
                            log("INFO", f"{Fore.RED}{Style.BRIGHT}Ping check failed{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}: {Fore.GREEN}{Style.BRIGHT}{target}{Style.RESET_ALL} {Fore.RED}TARGET{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}FAIL{Style.RESET_ALL}", console=True)
                    except Exception as e:
                        spinner.stop()
                        log("ERROR", f"{Fore.RED}{Style.BRIGHT}ERROR RUNNING PING{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}: {e}{Style.RESET_ALL}", console=True)

                    return target, target_type

    def distribute_work(
        self, ip: str, open_ports: Dict[str, List[int]], scanners: Scanners
    ) -> Dict[
        str, Dict[int, Mapping[str, Union[str, List[str], Mapping[str, str]]]]
    ]:
        init()
        detailed_results: Dict[str, Dict[int, Mapping[str, Union[str, List[str], Mapping[str, str]]]]] = {"tcp": {}, "udp": {}}
        total_ports = sum(len(ports) for ports in open_ports.values())
        completed: Dict[str, int] = {"total": total_ports, "count": 0}
        current_port: Dict[str, Optional[int]] = {"port": None}

        spinner_text = ''.join([Fore.MAGENTA, Style.BRIGHT, 'STAY CALM', Style.RESET_ALL])
        spinner: Halo = Halo(text=spinner_text, spinner='dots')
        colors: List[str] = [Fore.RED, Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.CYAN, Fore.MAGENTA, Fore.WHITE]
        color_cycle: Any = cycle(colors)
        stop_event = threading.Event()

        def update_spinner() -> None:
            while not stop_event.is_set():
                color: str = next(color_cycle)
                percentage: float = (completed['count'] / completed['total']) * 100
                spinner.text = (
                    f'{color}{Style.BRIGHT}STAY CALM {Style.RESET_ALL}'
                    f'{Fore.GREEN}{Style.BRIGHT}[{Fore.WHITE}{Style.BRIGHT}Port{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{current_port["port"]}{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}] '
                    f'{Fore.GREEN}{Style.BRIGHT}[{Fore.MAGENTA}{Style.BRIGHT}SCANNED{Style.RESET_ALL}'
                    f'{Fore.CYAN}{Style.BRIGHT}:{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}'
                    f'{completed["count"]}{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}/{Style.RESET_ALL}'
                    f'{completed["total"]}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT} '
                    f'{Fore.YELLOW}{Style.BRIGHT}PROGRESS{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}'
                    f'{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{percentage:.2f}{Fore.RED}{Style.BRIGHT}%{Style.RESET_ALL}'
                    f'{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}]'
                )
                time.sleep(0.1)

        threading.Thread(target=update_spinner, daemon=True).start()

        def worker(ip: str, port: int, proto: str) -> Dict[int, Optional[Mapping[str, Union[str, List[str], Mapping[str, str]]]]]:
            results: Dict[int, Optional[Mapping[str, Union[str, List[str], Mapping[str, str]]]]] = {}
            try:
                scanners.logger.debug(f"Worker started for {ip}:{port}/{proto}")
                port_result = scanners.scan_port(ip, port, proto)
                if port_result[1]:
                    results[port_result[0]] = port_result[1]
                scanners.logger.debug(f"Worker finished for {ip}:{port}/{proto}, got result: {port_result[1]}")
            except Exception as e:
                log(
                    "ERROR",
                    f"{Fore.RED}{Style.BRIGHT}Error Occurred During Scanning And Update For Port{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}{port}{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}on IP{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}{ip}: {e}{Style.RESET_ALL}",
                    console=False,
                )
            return results

        with ThreadPoolExecutor(max_workers=self.dynamic_worker_count()) as executor:
            futures: Dict[int, concurrent.futures.Future[Dict[int, Optional[Mapping[str, Union[str, List[str], Mapping[str, str]]]]]]] = {}
            proto_results_mapping: Dict[str,List[concurrent.futures.Future[Dict[int,Optional[Mapping[str,Union[str,List[str],Mapping[str,str]]]]]]]] = {
                "tcp": [],
                "udp": [],
            }
            if open_ports["tcp"] or open_ports["udp"]:
                log("INFO", f"{Fore.CYAN}{Style.BRIGHT}Performing Detailed Scan On{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}OPEN PORTS{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{total_ports}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}", console=True)
                spinner.start()  # type: ignore
            for proto, ports_list in open_ports.items():
                for port in ports_list:
                    scanners.logger.debug(f"Submitting scanning task for {ip}:{port}/{proto}")
                    future = executor.submit(worker, ip, port, proto)
                    futures[port] = future
                    proto_results_mapping[proto].append(future)

            for proto, future_list in proto_results_mapping.items():
                for future in as_completed(future_list):
                    scanned_port = next((p for p, f in futures.items() if f == future), None)
                    if scanned_port is not None:
                        current_port["port"] = scanned_port
                    proto_results = future.result()
                    for p, result in proto_results.items():
                        if result is not None:
                            detailed_results[proto][p] = result
                        completed["count"] += 1

        stop_event.set()
        spinner.stop()

        logged_ports: Set[int] = set()
        for ports_info in detailed_results.values():
            for port, info in ports_info.items():
                if port not in logged_ports:
                    if info:
                        log(
                            "",
                            f"\n{Fore.BLUE}{Style.BRIGHT}OPEN PORT{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}~{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{port}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}",
                            console=True,
                        )
                    fields: List[str] = [
                        "state",
                        "name",
                        "product",
                        "version",
                        "address",
                        "machine",
                        "memory",
                        "mac",
                        "mac_vendor",
                        "device",
                        "network",
                        "extrainfo",
                        "reason",
                        "osclass",
                        "osmatch",
                        "osfamily",
                        "hostname",
                        "hostnames",
                        "hostname_type",
                        "ipv4",
                        "ipv6",
                        "ipv4-id",
                        "ipv6 id",
                        "osgen",
                        "osaccuracy",
                        "vlan id",
                        "vlan name",
                        "distance",
                        "tcp_sequence",
                        "tcp_options",
                        "service_info",
                    ]
                    for field in fields:
                        if field in info and info[field] not in [
                            "",
                            "Not available",
                            "None",
                        ]:
                            if field == "state":
                                log(
                                    "INFO",
                                    f"{Fore.GREEN}{Style.BRIGHT}State{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{info['state']}{Style.RESET_ALL}",
                                    console=True,
                                )
                            elif field == "name":
                                log(
                                    "INFO",
                                    f"{Fore.BLUE}{Style.BRIGHT}Name{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}{info['name']}{Style.RESET_ALL}",
                                    console=True,
                                )
                            elif field == "product":
                                log(
                                    "INFO",
                                    f"{Fore.BLUE}{Style.BRIGHT}Product{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{info['product']}{Style.RESET_ALL}",
                                    console=True,
                                )
                            else:
                                log(
                                    "INFO",
                                    f"{Fore.BLUE}{field.capitalize()}{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{info[field]}{Style.RESET_ALL}",
                                    console=True,
                                )
                    log(
                        "INFO",
                        f"{Fore.YELLOW}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.BLUE}{Style.BRIGHT}~NMAP SCRIPTS OUTPUT BELOW IF FOUND~{Style.RESET_ALL}{Fore.YELLOW}{Style.BRIGHT}]{Style.RESET_ALL}",
                        console=True,
                    )
                    script_info = info.get("script", {})
                    logged_warnings: Set[str] = set()
                    if isinstance(script_info, dict):
                        for key, value in script_info.items():
                            if "vuln" in key.lower() or "cve" in key.lower():
                                if key not in logged_warnings:
                                    print(
                                        f"{Fore.GREEN}{Style.BRIGHT}[[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}-WARNING-{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}]]{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT} !POSSIBLE! VULNs{Style.RESET_ALL} {Fore.MAGENTA}{Style.BRIGHT}~OR~{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}CVEs !DETECTED!{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}[[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}-WARNING-{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}]]{Style.RESET_ALL}"
                                    )
                                    logged_warnings.add(key)
                                print(
                                    f"{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{key}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}vvvv=====>{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{value}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}<=====^^^^{Style.RESET_ALL}"
                                )
                            elif "certificate" in key.lower():
                                self.print_certificate(str(value))
                                log(
                                    "INFO",
                                    f"{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{key}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}{value}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}",
                                    console=True,
                                )
                            else:
                                log(
                                    "INFO",
                                    f"{Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.YELLOW}{Style.BRIGHT}{key}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.RED}{value}{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}]{Style.RESET_ALL}",
                                    console=True,
                                )
                    else:
                        log(
                            "ERROR",
                            f"{Fore.RED}{Style.BRIGHT}No script output{Style.RESET_ALL}",
                            console=True,
                        )
                    logged_ports.add(port)

        return detailed_results

    @staticmethod
    def print_warning(message: str) -> None:
        print(f"{Fore.RED}{Style.BRIGHT}{message}{Style.RESET_ALL}")

    @staticmethod
    def print_certificate(cert_text: str) -> None:
        cert_lines: List[str] = cert_text.split("\n")
        for line in cert_lines:
            if "BEGIN CERTIFICATE" in line or "END CERTIFICATE" in line:
                log("INFO", f"{Fore.YELLOW}{Style.BRIGHT}{line}{Style.RESET_ALL}")
            else:
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}")

    def display_scanner_results(self, scanner_results: Dict[str, Optional[str]]):
        for scanner_name, output in scanner_results.items():
            if output:
                method_name = f"display_{scanner_name}_result"
                method = getattr(self, method_name, None)
                if method:
                    method(output)
                else:
                    log(
                        "INFO",
                        f"\n{Fore.BLUE}{Style.BRIGHT}{scanner_name.upper()} RESULTS:{Style.RESET_ALL}",
                        console=True,
                    )
                    output_lines = output.strip().split("\n")
                    for line in output_lines:
                        log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_ping_check_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}PING CHECK RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if "bytes from" in line or "Reply from" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif "Destination Host Unreachable" in line or "Request timed out" in line:
                log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
            elif "ping statistics" in line or "Packets:" in line:
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_nslookup_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}NSLOOKUP RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if "Name:" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif "Address:" in line:
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif "Non-authoritative answer" in line:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_resolve_dns_name_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}RESOLVE-DNSNAME RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if "Name" in line and "Type" in line:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif "Name" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif "Type" in line or "TTL" in line:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif "IPV4Address" in line or "IPV6Address" in line:
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_traceroute_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}TRACEROUTE RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if "*" in line:
                log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*\d+\s", line):
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif "traceroute to" in line.lower() or "Tracing route to" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_whois_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}WHOIS RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        filtered_lines = [line for line in lines if "REDACTED FOR PRIVACY" not in line]
        for line in filtered_lines:
            if any(keyword in line for keyword in ["Domain Name:", "Registrant Name:", "Organization:", "Registrar:"]):
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif any(keyword in line for keyword in ["Updated Date:", "Creation Date:", "Registry Expiry Date:"]):
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif any(keyword in line for keyword in ["Name Server:", "DNSSEC:", "Status:"]):
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif ">>> Last update of whois database:" in line:
                log("INFO", f"{Fore.MAGENTA}{line}{Style.RESET_ALL}", console=True)

    def display_test_net_connection_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}TEST-NETCONNECTION RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if re.match(r"^\s*ComputerName\s+:\s+", line):
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*RemoteAddress\s+:\s+", line):
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*RemotePort\s+:\s+", line):
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*TcpTestSucceeded\s+:\s+True", line):
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*TcpTestSucceeded\s+:\s+False", line):
                log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_test_connection_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}TEST-CONNECTION RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if re.match(r"^\s*Source\s+:\s+", line):
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*Destination\s+:\s+", line):
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*PingSucceeded\s+:\s+True", line):
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*PingSucceeded\s+:\s+False", line):
                log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*PingReplyDetails", line):
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_get_net_tcp_connection_result(self, output: str) -> None:
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}GET-NETTCPCONNECTION RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines: List[str] = output.strip().split("\n")
        remove_if_contains = [
            "TimeWait",
            "Bound",
            "Listen",
            "CloseWait",
        ]
        filtered_lines: List[str] = []
        for line in lines:
            clean_line: str = line.strip()
            if not clean_line or any(kw.lower() in clean_line.lower() for kw in remove_if_contains):
                continue
            filtered_lines.append(clean_line)

        header: bool = True
        for line in filtered_lines:
            if header:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
                if re.match(r"^-+$", line.strip()):
                    header = False
            else:
                if "Established" in line:
                    log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
                else:
                    log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_get_net_adapter_result(self, output: str) -> None:
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}GET-NETADAPTER RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines: List[str] = output.strip().split("\n")
        remove_if_contains = [
            "TimeWait",
            "Bound",
            "Listen",
            "CloseWait",
        ]
        filtered_lines: List[str] = []
        for line in lines:
            clean_line: str = line.strip()
            if not clean_line or any(kw.lower() in clean_line.lower() for kw in remove_if_contains):
                continue
            filtered_lines.append(clean_line)

        header: bool = True
        for line in filtered_lines:
            if header:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
                if re.match(r"^-+$", line.strip()):
                    header = False
            else:
                if "Up" in line:
                    log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
                elif "Down" in line:
                    log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
                elif "Disabled" in line:
                    log("INFO", f"{Fore.MAGENTA}{line}{Style.RESET_ALL}", console=True)
                else:
                    log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_get_net_ip_configuration_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}GET-NETIPCONFIGURATION RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if re.match(r"^\s*InterfaceAlias\s+:\s+", line):
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*IPv4Address\s+:\s+", line):
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*IPv6Address\s+:\s+", line):
                log("INFO", f"{Fore.MAGENTA}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*DefaultGateway\s+:\s+", line):
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif re.match(r"^\s*DNSServer\s+:\s+", line):
                log("INFO", f"{Fore.BLUE}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_get_net_route_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}GET-NETROUTE RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        header = True
        for line in lines:
            if header:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
                if re.match(r"^-+$", line.strip()):
                    header = False
            elif "0.0.0.0" in line or "::/0" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_get_net_neighbor_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}GET-NETNEIGHBOR RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        header = True
        for line in lines:
            if header:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
                if re.match(r"^-+$", line.strip()):
                    header = False
            elif "Reachable" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif "Unreachable" in line or "Stale" in line:
                log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
            elif "Probe" in line:
                log("INFO", f"{Fore.MAGENTA}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_invoke_web_request_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}INVOKE-WEBREQUEST RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        in_headers = False
        in_content = False
        for line in lines:
            if line.startswith("HTTP/"):
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif line.strip() == "Headers":
                in_headers = True
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif line.strip() == "RawContent":
                in_headers = False
                in_content = True
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif in_headers:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif in_content:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)
            elif "StatusCode" in line or "StatusDescription" in line:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_curl_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}CURL RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if line.startswith("*"):
                log("INFO", f"{Fore.MAGENTA}{line}{Style.RESET_ALL}", console=True)
            elif line.startswith(">") or line.startswith("<"):
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_openssl_scan_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}OPENSSL SCAN RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if "Certificate chain" in line:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif "Server certificate" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif "Verify return code" in line:
                if "0 (ok)" in line:
                    log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
                else:
                    log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
            elif "New, TLSv1" in line or "Cipher" in line:
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            else:
                log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def display_advanced_nslookup_result(self, output: str):
        log(
            "INFO",
            f"\n{Fore.BLUE}{Style.BRIGHT}ADVANCED NSLOOKUP RESULTS:{Style.RESET_ALL}",
            console=True,
        )
        lines = output.strip().split("\n")
        for line in lines:
            if "Name:" in line:
                log("INFO", f"{Fore.GREEN}{line}{Style.RESET_ALL}", console=True)
            elif "Address:" in line or "Addresses:" in line:
                log("INFO", f"{Fore.CYAN}{line}{Style.RESET_ALL}", console=True)
            elif "Aliases:" in line:
                log("INFO", f"{Fore.YELLOW}{line}{Style.RESET_ALL}", console=True)
            elif "Non-authoritative answer" in line:
                log("INFO", f"{Fore.MAGENTA}{line}{Style.RESET_ALL}", console=True)
            elif "DNS request timed out" in line:
                log("INFO", f"{Fore.RED}{line}{Style.RESET_ALL}", console=True)
            elif line.strip() == "":
                pass
            else:
                if re.match(r"^\S+\s+\d+\s+IN\s+\w+\s+.+", line):
                    log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)
                else:
                    log("INFO", f"{Fore.WHITE}{line}{Style.RESET_ALL}", console=True)

    def main(self):
        def wait_for_user_input(stop_event: threading.Event) -> None:
            """Pauses until the user presses Enter, then sets stop_event."""
            input(f"{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
            stop_event.set()

        def print_ascii_art():
            colors = [
                Fore.RED, Fore.GREEN, Fore.BLUE, Fore.YELLOW, Fore.CYAN,
                Fore.MAGENTA, Fore.BLACK, Fore.LIGHTBLACK_EX, Fore.LIGHTBLUE_EX,
                Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTMAGENTA_EX,
                Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTYELLOW_EX
            ]
            color_cycle = itertools.cycle(colors)

            ascii_art_lines = [
                Style.BRIGHT + Fore.RED + "              .                                                       .",
                Style.BRIGHT + Fore.RED + "            .n                   .                  .                  n.",
                Style.BRIGHT + Fore.RED + "      .   .dP                  dP                    9b                 9b.    .",
                Style.BRIGHT + Fore.RED + "     4    qXb         4       dX          4           Xb       4        dXp     X",
                Style.BRIGHT + Fore.RED + "    dX.   9XXb.     dXb.    .dXb_        ...         _dXb.   .dXb     .9XXb    .d3",
                Style.BRIGHT + Fore.RED + "    9XXb._ XXXXb  .dXXXXb dXXXXbo.      xxAxx       .odXXXXb dXXXXb.  XXXXb _.dXXP",
                Style.BRIGHT + Fore.RED + "     9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.xxWXXAXXWxx.oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP",
                Style.BRIGHT + Fore.RED + "      `9XXXXXXXXXXXXXXXXXXXXXXX'~   ~OOO8bXd8OOO~   ~`XXXXXXXXXXXXXXXXXXXXXXXP'",
                Style.BRIGHT + Fore.RED + "        `9XXXXXXXXXXXP' `9XX'            XxX           `XXP' `9XXXXXXXXXXXP'",
                Style.BRIGHT + Fore.RED + "            ~~~~~~~       9X.          .98v8P.          .XP       ~~~~~~~",
                Style.BRIGHT + Fore.RED + "              xwWw        9x.          .dbXdb.          .xp         wWwx  ",
                Style.BRIGHT + Fore.RED + "               V            )b.  .dbo.dP'`v'`9b.odb.  .dX(            V",
                Style.BRIGHT + Fore.RED + "                          ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.",
                Style.BRIGHT + Fore.RED + "                         dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb",
                Style.BRIGHT + Fore.RED + "                        dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb",
                Style.BRIGHT + Fore.RED + "                        9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP",
                Style.BRIGHT + Fore.RED + "                         V       9XXXXXX(   )XXXXXXP      V",
                Style.BRIGHT + Fore.RED + "                                  XXXX X.`v'.X XXXX",
                Style.BRIGHT + Fore.RED + "                                  XP^X'`b   d'`X^XX",
                Style.BRIGHT + Fore.RED + "                                  X. 9  `   '  P )X",
                Style.BRIGHT + Fore.RED + "                                  `b  `       '  d'",
                Style.BRIGHT + Fore.RED + "                                   `             '",
                Fore.BLUE + "READ " + Fore.RED + ":" + Fore.WHITE + " This tool is for educational purposes only." + Style.RESET_ALL,
                Fore.BLUE + "DEV  " + Fore.RED + ":" + Fore.WHITE + " Dr4gnf1y / https://github.com/Dr4gnf1y" + Style.RESET_ALL,
                Fore.GREEN + "USER " + Fore.RED + ":" + Fore.YELLOW + " PRESS ENTER TO BEGIN USER INPUT"
            ]

            stop_event = threading.Event()

            def update_flashing_text() -> None:
                while not stop_event.is_set():
                    color = next(color_cycle)
                    flashing_text = (
                        f"{Style.BRIGHT}{color}  STAY{Style.RESET_ALL}    "
                        f"{Style.BRIGHT}{Fore.RED}.98v8P.{Style.RESET_ALL}  "
                        f"{Style.BRIGHT}{color} CALM{Style.RESET_ALL}"
                    )
                    ascii_art_lines[9] = (
                        Style.BRIGHT + Fore.RED +
                        "           ~~~~~~~       9X. " + flashing_text + Style.BRIGHT + Fore.RED + "   .XP        ~~~~~~~"
                    )
                    print("\033[H\033[J" + "\n".join(ascii_art_lines))
                    time.sleep(0.05)

            flashing_thread = threading.Thread(target=update_flashing_text, daemon=True)
            flashing_thread.start()

            input_thread = threading.Thread(target=wait_for_user_input, args=(stop_event,))
            input_thread.start()

            input_thread.join()
            stop_event.set()

            flashing_thread.join()

        print_ascii_art()
        start_time = time.time()
        target, target_type = self.get_target()
        tag = target.replace(".", "_")
        if target_type == "domain":
            resolved_ip = self.resolve_hostname(target)
            if resolved_ip:
                target_ip = resolved_ip
            else:
                log(
                    "ERROR",
                    f"{Fore.RED}{Style.BRIGHT}Invalid domain: {target}{Style.RESET_ALL}",
                    console=True,
                )
                return
        else:
            target_ip = target
        log(
            "INFO",
            f"{Fore.MAGENTA}{Style.BRIGHT}Setting Up Scan On{Style.RESET_ALL} {Fore.MAGENTA}{Style.BRIGHT}[{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}{target}{Style.RESET_ALL}{Fore.MAGENTA}{Style.BRIGHT}]{Style.RESET_ALL}",
            console=True,
        )
        open_ports: Dict[str, List[int]] = {"tcp": [], "udp": []}

        scanners = Scanners(target, target_type, self.logger)

        scanner_results: Dict[str, Optional[str]] = {}
        scanner_results["ping_check"] = scanners.run_ping_check()
        scanner_results["nslookup"] = scanners.run_nslookup()
        scanner_results["resolve_dns_name"] = scanners.run_resolve_dns_name()

        scanner_results["traceroute"] = scanners.run_traceroute()
        scanner_results["whois"] = scanners.run_whois()
        scanner_results["test_net_connection"] = scanners.run_test_net_connection()
        scanner_results["test_connection"] = scanners.run_test_connection()

        scanner_results["get_net_tcp_connection"] = scanners.run_get_net_tcp_connection()
        scanner_results["get_net_adapter"] = scanners.run_get_net_adapter()
        scanner_results["get_net_ip_configuration"] = scanners.run_get_net_ip_configuration()
        scanner_results["get_net_route"] = scanners.run_get_net_route()
        scanner_results["get_net_neighbor"] = scanners.run_get_net_neighbor()

        try:
            open_ports = scanners.quick_scan(target_ip)
            log(
                "INFO",
                f"{Fore.GREEN}{Style.BRIGHT}Quick Scan Completed.{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}Identified{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}OPEN PORTS{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}:{Style.RESET_ALL}",
                console=True,
            )
            if open_ports["tcp"]:
                formatted_tcp_ports = self.format_ports(open_ports["tcp"])
                log("INFO", f"{Fore.GREEN}{Style.BRIGHT}\n{formatted_tcp_ports}{Style.RESET_ALL}", console=True)
            if open_ports["udp"] and len(open_ports["udp"]) > 0:
                formatted_udp_ports = self.format_ports(open_ports["udp"])
                log("INFO", f"{Fore.GREEN}{Style.BRIGHT}\n{formatted_udp_ports}{Style.RESET_ALL}", console=True)
        except Exception as e:
            log("ERROR", f"{Fore.RED}{Style.BRIGHT}Error Occurred During Scan: {e}{Style.RESET_ALL}", console=True)
            return

        if platform.system() == "Windows" and open_ports["tcp"]:
            for port in open_ports["tcp"]:
                scanner_results[f"test_net_connection_port_{port}"] = scanners.run_command(
                    [
                        "powershell.exe",
                        "-Command",
                        f"Test-NetConnection -ComputerName {target} -Port {port}",
                    ],
                    f"Test-NetConnection Port {port}",
                    max_workers_override=scanners.dynamic_worker_count()
                )

        detailed_results: Dict[
            str, Dict[int, Mapping[str, Union[str, List[str], Mapping[str, str]]]]
        ] = {"tcp": {}, "udp": {}}
        if open_ports["tcp"] or open_ports["udp"]:
            try:
                detailed_results = self.distribute_work(target_ip, open_ports, scanners)
            except Exception as e:
                log("ERROR", f"{Fore.RED}{Style.BRIGHT}Error Occurred During Detailed Scan: {e}{Style.RESET_ALL}", console=True)
                return

        if 80 in open_ports["tcp"] or 443 in open_ports["tcp"]:
            scanner_results["invoke_web_request"] = scanners.run_invoke_web_request()
            scanner_results["curl"] = scanners.run_curl()
            scanner_results["openssl_scan"] = scanners.run_openssl_scan()
        if 53 in open_ports["udp"]:
            scanner_results["advanced_nslookup"] = scanners.run_advanced_nslookup()

        pseudo_port_start = 60000
        for s_name, s_output in scanner_results.items():
            if s_output and s_name not in ["ping_check","nslookup","resolve_dns_name","traceroute","whois","test_net_connection","test_connection","get_net_tcp_connection","get_net_adapter","get_net_ip_configuration","get_net_route","get_net_neighbor","invoke_web_request","curl","openssl_scan","advanced_nslookup"]:
                lines = s_output.strip().split("\n")
                port_info: Dict[str, Union[str, List[str], Mapping[str, str]]] = {}
                port_info["raw_output"] = lines
                vulnerability_found = False
                vulnerability_details: List[str] = []
                for line in lines:
                    lower_line: str = line.lower()
                    if "vuln" in lower_line or "cve" in lower_line or "exploit" in lower_line:
                        vulnerability_found = True
                        vulnerability_details.append(line)

                if vulnerability_found:
                    port_info["Warning_scanner"] = "[[-WARNING-]] !POSSIBLE! VULNs ~OR~ CVEs !DETECTED! [[-WARNING-]]"
                    port_info["vulnerabilities"] = vulnerability_details

                pseudo_port = pseudo_port_start
                pseudo_port_start += 1
                if "scanners" not in detailed_results:
                    detailed_results["scanners"] = {}
                detailed_results["scanners"][pseudo_port] = port_info

        self.report_generator.save_reports(detailed_results, scanner_results, tag)
        self.display_scanner_results(scanner_results)

        elapsed_time = time.time() - start_time
        hours = int(elapsed_time // 3600)
        minutes = int((elapsed_time % 3600) // 60)
        seconds = int(elapsed_time % 60)
        log(
            "INFO",
            f"{Fore.WHITE}{Style.BRIGHT}TOTAL SCAN COMPLETED IN{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}{Fore.MAGENTA}{Style.BRIGHT}[{Style.RESET_ALL}{hours:02d}:{minutes:02d}:{seconds:02d}{Style.RESET_ALL}{Fore.MAGENTA}{Style.BRIGHT}]{Style.RESET_ALL}",
            console=True,
        )

if __name__ == "__main__":
    try:
        cluster = LocalCluster(n_workers=4, threads_per_worker=2)
        client = Client(cluster)
    except CommClosedError as e:
        log("ERROR", f"Dask communication error: {e}", console=False)
        sys.exit(1)
    except Exception as e:
        log("ERROR", f"Unexpected error initializing Dask: {e}", console=False)
        sys.exit(1)
    ModuleInstaller.install_system_dependencies_once()
    staycalm_scan = StayCalmScan()
    staycalm_scan.main()
