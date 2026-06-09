#!/usr/bin/env python3
"""Bulk HTTP/HTTPS collector scanner for network devices.

This script scans hosts by IP address, range, or subnet, detects valid
targets based on page content, and uses collector modules to download
config backups. It writes a detailed log plus a simple summary file.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import logging
import os
import re
import sys
import warnings
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

# Ensure repo root is importable when running this script directly.
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config_collector_http_aruba_instant_on import (
    attempt_login,
    download_backup,
    fetch_encryption_settings,
    fetch_initial_login_page,
    get_document_root,
)

from requests import RequestException, Session

TARGET_DEFINITIONS = {
    "Aruba Instant On": [
        "welcome to aruba instant on",
        "inputusername",
        "aruba instant on",
    ],
}

DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bulk scan hosts, detect valid targets, and download device configs."
    )
    parser.add_argument(
        "--targets",
        required=True,
        help=(
            "Single IP/host, comma-separated IPs/hosts, IP ranges, subnets, or subnet ranges. "
            "Examples: 10.1.1.1,10.1.1.5-10.1.1.10,10.1.2.0/24,10.1.0.0/24-10.1.3.0/24"
        ),
    )
    parser.add_argument(
        "--targets-file",
        help="Optional file with one target per line to scan in addition to --targets.",
    )
    parser.add_argument(
        "--download-root",
        default="downloads",
        help="Root directory for all downloaded configuration files.",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory to write the detailed and summary log files.",
    )
    parser.add_argument(
        "--protocol",
        choices=["any", "https", "http"],
        default="any",
        help="Protocol to attempt first when scanning (default: any).",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Override both HTTP and HTTPS ports with a single value.",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=DEFAULT_HTTP_PORT,
        help="Custom HTTP port (default: 80).",
    )
    parser.add_argument(
        "--https-port",
        type=int,
        default=DEFAULT_HTTPS_PORT,
        help="Custom HTTPS port (default: 443).",
    )
    parser.add_argument("--username", help="Default username for all targets.")
    parser.add_argument("--password", help="Default password for all targets.")
    parser.add_argument(
        "--credentials-csv",
        help=(
            "CSV file with host,username,password columns to override credentials for individual hosts. "
            "Expected CSV header: host,username,password"
        ),
    )
    parser.add_argument(
        "--allow-insecure",
        action="store_true",
        help="Allow insecure SSL/TLS connections when using HTTPS.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print scan progress to the console.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Network timeout in seconds for HTTP requests.",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=1,
        help="Number of connection attempts per protocol for each host (default: 1).",
    )
    parser.add_argument(
        "--max-host-seconds",
        type=float,
        default=0.0,
        help=(
            "Maximum total seconds to spend attempting a single host across all protocols and attempts. "
            "Set to 0 to disable (default: 0)."
        ),
    )
    return parser.parse_args()


def normalize_host_token(token: str) -> str:
    return token.strip()


def parse_hosts_from_targets(targets: str, targets_file: Optional[str]) -> List[str]:
    raw_values: List[str] = []
    raw_values.extend(value.strip() for value in targets.split(",") if value.strip())
    if targets_file:
        file_path = Path(targets_file)
        if not file_path.exists():
            raise FileNotFoundError(f"Targets file not found: {file_path}")
        raw_values.extend(
            line.strip() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()
        )

    hosts: List[str] = []
    for raw in raw_values:
        hosts.extend(expand_target_expression(raw))
    return hosts


def expand_target_expression(expression: str) -> List[str]:
    expression = expression.strip()
    if not expression:
        return []

    if "-" in expression and "/" in expression:
        left, right = expression.split("-", 1)
        left = left.strip()
        right = right.strip()
        try:
            left_net = ipaddress.ip_network(left, strict=False)
            right_net = ipaddress.ip_network(right, strict=False)
            return [str(host) for network in expand_subnet_range(left_net, right_net) for host in network.hosts()]
        except ValueError:
            pass

    if "/" in expression:
        try:
            network = ipaddress.ip_network(expression, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError:
            return [expression]

    if "-" in expression:
        left, right = expression.split("-", 1)
        left = left.strip()
        right = right.strip()
        try:
            start_ip = ipaddress.ip_address(left)
            end_ip = ipaddress.ip_address(right)
            return [str(host) for host in expand_ip_range(start_ip, end_ip)]
        except ValueError:
            return [expression]

    return [expression]


def expand_ip_range(start_ip: ipaddress._BaseAddress, end_ip: ipaddress._BaseAddress) -> Iterator[ipaddress._BaseAddress]:
    if type(start_ip) is not type(end_ip):
        raise ValueError("IP range endpoints must be the same IP version.")
    if int(start_ip) > int(end_ip):
        raise ValueError("IP range start must be less than or equal to end.")

    current = int(start_ip)
    last = int(end_ip)
    while current <= last:
        yield ipaddress.ip_address(current)
        current += 1


def expand_subnet_range(
    start_net: ipaddress._BaseNetwork, end_net: ipaddress._BaseNetwork
) -> Iterator[ipaddress._BaseNetwork]:
    if start_net.version != end_net.version:
        raise ValueError("Subnet range endpoints must be the same IP version.")
    if start_net.prefixlen != end_net.prefixlen:
        raise ValueError("Subnet range endpoints must use the same prefix length.")
    if int(start_net.network_address) > int(end_net.network_address):
        raise ValueError("Subnet range start must be less than or equal to end.")

    step = start_net.num_addresses
    current = int(start_net.network_address)
    end_value = int(end_net.network_address)
    while current <= end_value:
        yield ipaddress.ip_network((current, start_net.prefixlen), strict=False)
        current += step


def load_host_credentials(csv_path: Optional[str]) -> dict[str, Tuple[str, str]]:
    # Expected CSV format:
    # host,username,password
    # 10.1.1.245,admin,Secret123
    # 10.1.1.246,admin2,Secret456
    credentials: dict[str, Tuple[str, str]] = {}
    if not csv_path:
        return credentials

    csv_file = Path(csv_path)
    if not csv_file.exists():
        raise FileNotFoundError(f"Credentials CSV not found: {csv_file}")

    with csv_file.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            host_key = row.get("host") or row.get("Host") or row.get("hostname") or row.get("Hostname")
            username = row.get("username") or row.get("Username")
            password = row.get("password") or row.get("Password")
            if not host_key or not username or not password:
                continue
            credentials[host_key.strip()] = (username.strip(), password.strip())
    return credentials


def identify_target(response_text: str) -> Optional[str]:
    lowered = response_text.lower()
    for target_name, patterns in TARGET_DEFINITIONS.items():
        for pattern in patterns:
            if pattern.lower() in lowered:
                return target_name
    return None


def format_host_port(host: str, port: int) -> str:
    try:
        addr = ipaddress.ip_address(host)
        if addr.version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


def sanitize_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    return cleaned.strip("_") or "host"


def setup_logger(log_file: Path, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("bulk_collector_http_scan")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(file_handler)

    # Mirror detailed file log to the terminal so users can see progress live.
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(stream_handler)

    return logger


def build_url(protocol: str, host_with_port: str, path: str = "/") -> str:
    return f"{protocol}://{host_with_port}{path}"


def request_host_page(
    session: Session,
    protocol: str,
    host_with_port: str,
    timeout: int,
    verify: bool,
) -> Optional[str]:
    url = build_url(protocol, host_with_port, "/")
    response = session.get(url, timeout=timeout, allow_redirects=True, verify=verify)
    response.raise_for_status()
    return response.text


def collect_aruba_instant_on(
    session: Session,
    host: str,
    port: int,
    protocol: str,
    username: str,
    password: str,
    download_root: Path,
    allow_insecure: bool,
    timeout: int,
    logger: logging.Logger,
) -> Tuple[bool, Optional[Path], str]:
    host_with_port = format_host_port(host, port)
    verify = not allow_insecure
    if not verify:
        warnings.filterwarnings("ignore", category=UserWarning)

    safe_host = sanitize_filename(host)
    target_folder = download_root / "Aruba_Instant_On" / safe_host
    target_folder.mkdir(parents=True, exist_ok=True)
    output_path = target_folder / f"{safe_host}_aruba_instant_on.config"

    stdout_buffer = StringIO()
    success = False
    log_text = ""

    with redirect_stdout(stdout_buffer):
        try:
            document_root, initial_location = get_document_root(
                session=session,
                protocol=protocol,
                host=host_with_port,
                verify=verify,
                debug=True,
            )
            fetch_initial_login_page(
                session=session,
                protocol=protocol,
                host=host_with_port,
                location=initial_location,
                verify=verify,
                debug=True,
            )
            rsa_public_key, login_token, passw_encrypt_enable = fetch_encryption_settings(
                session=session,
                protocol=protocol,
                host=host_with_port,
                verify=verify,
                debug=True,
            )
            if not attempt_login(
                session=session,
                protocol=protocol,
                host=host_with_port,
                document_root=document_root,
                username=username,
                password=password,
                login_token=login_token,
                rsa_public_key=rsa_public_key,
                passw_encrypt_enable=passw_encrypt_enable,
                verify=verify,
                verbose=True,
                debug=True,
            ):
                raise RuntimeError("Login failed for Aruba Instant On target.")
            content = download_backup(
                session=session,
                protocol=protocol,
                host=host_with_port,
                document_root=document_root,
                verify=verify,
                debug=True,
            )
            with open(output_path, "wb") as handle:
                handle.write(content)
            success = True
        except Exception as exc:
            print(f"ERROR: {exc}")
        finally:
            log_text = stdout_buffer.getvalue()

    logger.info("Collector output for %s (%s://%s):\n%s", host, protocol, host_with_port, log_text)
    return success, output_path if success else None, log_text


def scan_target(
    host: str,
    target_credentials: Tuple[Optional[str], Optional[str]],
    protocol_order: Sequence[str],
    http_port: int,
    https_port: int,
    download_root: Path,
    allow_insecure: bool,
    timeout: int,
    max_attempts: int,
    max_host_seconds: float,
    logger: logging.Logger,
) -> Tuple[Optional[str], str, bool, Optional[Path], str]:
    username, password = target_credentials
    if not username or not password:
        logger.warning("No credentials supplied for host %s; the host may still be detected as a valid target.", host)

    session = Session()
    session.headers.update({"User-Agent": "bulk-collector-http-scan/1.0"})
    verify = not allow_insecure
    if not verify:
        warnings.filterwarnings("ignore", category=UserWarning)

    # track total time spent on this host (across protocols/attempts)
    host_start = datetime.now().timestamp()

    for protocol in protocol_order:
        port = https_port if protocol == "https" else http_port
        host_with_port = format_host_port(host, port)

        for attempt in range(1, max(1, max_attempts) + 1):
            # check per-host time budget
            if max_host_seconds and (datetime.now().timestamp() - host_start) >= max_host_seconds:
                logger.info(
                    "Host %s reached max-host-seconds (%.1fs); aborting further attempts.", host, max_host_seconds
                )
                return None, "Fail", False, None, "Host time budget exceeded"

            try:
                logger.info("Scanning %s (attempt %d/%d) with %s://%s", host, attempt, max_attempts, protocol, host_with_port)
                page_text = request_host_page(
                    session=session,
                    protocol=protocol,
                    host_with_port=host_with_port,
                    timeout=timeout,
                    verify=verify,
                )
            except RequestException as exc:
                logger.info("Attempt %d: Unable to reach %s://%s: %s", attempt, protocol, host_with_port, exc)
                # try next attempt or protocol
                continue

            target_name = identify_target(page_text or "")
            if not target_name:
                logger.info("Host %s is not a known valid target for %s://%s.", host, protocol, host_with_port)
                # no need to retry same protocol if content isn't a target
                break

            logger.info("Detected valid target %s on host %s (%s://%s).", target_name, host, protocol, host_with_port)

            if not username or not password:
                logger.warning("Skipping collection for %s because credentials are missing.", host)
                return target_name, "Fail", False, None, "Credentials missing"

            if target_name == "Aruba Instant On":
                success, output_path, collector_log = collect_aruba_instant_on(
                    session=session,
                    host=host,
                    port=port,
                    protocol=protocol,
                    username=username,
                    password=password,
                    download_root=download_root,
                    allow_insecure=allow_insecure,
                    timeout=timeout,
                    logger=logger,
                )
                status = "Success" if success else "Fail"
                return target_name, status, success, output_path, collector_log

            logger.warning("No collector implemented for target %s.", target_name)
            return target_name, "Fail", False, None, "Collector not implemented"

    return None, "Fail", False, None, "No valid target detected"


def load_credentials(
    csv_credentials: dict[str, Tuple[str, str]],
    default_username: Optional[str],
    default_password: Optional[str],
    host: str,
) -> Tuple[Optional[str], Optional[str]]:
    if host in csv_credentials:
        return csv_credentials[host]
    return default_username, default_password


def run_scan(args: argparse.Namespace) -> int:
    download_root = Path(args.download_root)
    download_root.mkdir(parents=True, exist_ok=True)

    log_root = Path(args.log_dir)
    log_root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    detailed_log_path = log_root / f"bulk_scan_full_{timestamp}.log"
    summary_log_path = log_root / f"bulk_scan_summary_{timestamp}.log"

    logger = setup_logger(detailed_log_path, args.verbose)
    logger.info("Starting bulk collector scan.")

    if args.port is not None:
        http_port = https_port = args.port
    else:
        http_port = args.http_port
        https_port = args.https_port

    protocol_order: List[str] = []
    if args.protocol == "any":
        protocol_order = ["https", "http"]
    else:
        protocol_order = [args.protocol]

    csv_credentials = load_host_credentials(args.credentials_csv)
    hosts = parse_hosts_from_targets(args.targets, args.targets_file)
    unique_hosts = []
    seen: set[str] = set()
    for host in hosts:
        normalized = host.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique_hosts.append(normalized)

    logger.info("Resolved %d unique hosts to scan.", len(unique_hosts))

    with summary_log_path.open("w", encoding="utf-8") as summary_file:
        summary_file.write("Host IP,Target,Download Status,File Path\n")
        for host in unique_hosts:
            username, password = load_credentials(csv_credentials, args.username, args.password, host)
            target_name, status, success, output_path, collector_log = scan_target(
                host=host,
                target_credentials=(username, password),
                protocol_order=protocol_order,
                http_port=http_port,
                https_port=https_port,
                download_root=download_root,
                allow_insecure=args.allow_insecure,
                timeout=args.timeout,
                    max_attempts=args.max_attempts,
                    max_host_seconds=args.max_host_seconds,
                logger=logger,
            )
            if target_name:
                path_text = str(output_path) if output_path else ""
                summary_file.write(f"{host},{target_name},{status},{path_text}\n")
                summary_file.flush()
            else:
                logger.info("Host %s is not a valid target; skipping summary entry.", host)

    logger.info("Bulk scan complete. Detailed log: %s, summary log: %s", detailed_log_path, summary_log_path)
    print(f"Detailed log: {detailed_log_path}")
    print(f"Summary log: {summary_log_path}")
    return 0


def main() -> int:
    args = parse_args()
    try:
        return run_scan(args)
    except Exception as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
