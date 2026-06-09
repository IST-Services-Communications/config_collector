"""Aruba Instant ON 1930 switch backup download script.

This Python implementation is based on the working Perl example by Dariusz Zielinski-Kolasinski:
https://github.com/dkolasinski/aruba-instant-on-1930-backup-script

Original Perl script license: GPL-3.0
Author: Dariusz Zielinski-Kolasinski
Repository: https://github.com/dkolasinski/aruba-instant-on-1930-backup-script

It performs the same request sequence:
1) GET / and parse the redirect Location header to determine the document root.
2) GET the initial login page under the document root.
3) GET /device/wcd?{EncryptionSetting} to retrieve RSA key, login token and encryption flag.
4) Encrypt the login payload if required and perform the authenticated login.
5) Download the startup configuration from /<documentRoot>/hpe/http_download?action=3&ssd=4.

Usage examples:
	python config_collector_http_aruba_instant_on.py \
		--ip 10.1.1.245 \
		--name switch_name \
		--username admin \
		--password switch_password \
		--file switch_name.config \
		--allow-insecure

	python config_collector_http_aruba_instant_on.py \
		--ip 10.1.1.245 \
		--name switch_name \
		--username admin \
		--password switch_password \
		--protocol https \
		--allow-insecure \
		--debug
"""

import argparse
import os
import re
import sys
import warnings
from urllib.parse import quote, urlparse

REQUIRED_DEPENDENCIES = ["requests", "cryptography"]

try:
	import requests
	from requests.exceptions import RequestException, SSLError
	from cryptography.hazmat.primitives import serialization
	from cryptography.hazmat.primitives.asymmetric import padding
except ModuleNotFoundError as exc:
	missing_module = exc.name or "unknown"
	print(
		f"Missing Python dependency: {missing_module}.\n"
		f"Install the required dependencies with:\n"
		f"    python -m pip install {' '.join(REQUIRED_DEPENDENCIES)}\n"
		"If you are using a virtual environment, activate it before running the script.",
		file=sys.stderr,
	)
	raise SystemExit(1)


def build_url(protocol: str, host: str, path: str) -> str:
	return f"{protocol}://{host}{path}"


def make_absolute_url(protocol: str, host: str, location: str) -> str:
	if location.startswith("http://") or location.startswith("https://"):
		return location
	return build_url(protocol, host, location)


def parse_redirect_location(location: str) -> tuple[str, str]:
	if not location:
		raise ValueError("Missing Location header from initial request")
	parsed = urlparse(location)
	path = parsed.path or location
	if not path.startswith("/"):
		raise ValueError(f"Unexpected redirect location: {location}")
	match = re.match(r"^/([^/]+)", path)
	if not match:
		raise ValueError(f"Cannot parse document root from Location: {location}")
	return match.group(1), location


def get_document_root(session: requests.Session, protocol: str, host: str, verify: bool, debug: bool = False) -> tuple[str, str]:
	url = build_url(protocol, host, "/")
	if debug:
		print(f"req 1. GET {url}")
	response = session.get(url, verify=verify, allow_redirects=False, timeout=15)
	if debug:
		print(f"req 1. STATUS: {response.status_code}")
		print(f"req 1. LOCATION: {response.headers.get('Location', 'N/A')}")
	if not response.is_redirect:
		raise ValueError(f"Expected redirect from {protocol}://{host}, got {response.status_code}")
	return parse_redirect_location(response.headers.get("Location", ""))


def fetch_initial_login_page(session: requests.Session, protocol: str, host: str, location: str, verify: bool, debug: bool = False) -> str:
	url = make_absolute_url(protocol, host, location)
	if debug:
		print(f"req 2. GET {url}")
	response = session.get(url, verify=verify, timeout=20)
	response.raise_for_status()
	if debug:
		print(f"req 2. STATUS: {response.status_code}")
		if "inputUsername" in response.text:
			print("req 2. DETECTED: Aruba Instant ON")
		elif "UserCntrl" in response.text:
			print("req 2. DETECTED: Cisco CBS")
	return response.text


def fetch_encryption_settings(session: requests.Session, protocol: str, host: str, verify: bool, debug: bool = False) -> tuple[str, str, str]:
	url = build_url(protocol, host, "/device/wcd?{EncryptionSetting}")
	headers = {"Accept": "application/xml, text/xml"}
	if debug:
		print(f"req 3. GET {url}")
	response = session.get(url, verify=verify, headers=headers, timeout=20)
	response.raise_for_status()
	if debug:
		print(f"req 3. STATUS: {response.status_code}")
	content = response.text

	rsa_public_key_match = re.search(r"<rsaPublicKey>(.+?)</rsaPublicKey>", content, re.DOTALL)
	login_token_match = re.search(r"<loginToken>(.+?)</loginToken>", content, re.DOTALL)
	passw_encrypt_enable_match = re.search(r"<passwEncryptEnable>(.+?)</passwEncryptEnable>", content, re.DOTALL)

	if not rsa_public_key_match:
		raise ValueError("RSA public key not found in encryption settings")
	if not login_token_match:
		raise ValueError("Login token not found in encryption settings")
	if not passw_encrypt_enable_match:
		raise ValueError("Password encryption flag not found in encryption settings")

	rsa_public_key = rsa_public_key_match.group(1).strip()
	login_token = login_token_match.group(1).strip()
	passw_encrypt_enable = passw_encrypt_enable_match.group(1).strip()

	if debug:
		print(f"req 3. RSA KEY EXTRACTED: {rsa_public_key[:50]}...")
		print(f"req 3. LOGIN TOKEN: {login_token}")
		print(f"req 3. PASSWORD ENCRYPT ENABLE: {passw_encrypt_enable}")

	return rsa_public_key, login_token, passw_encrypt_enable


def load_rsa_public_key(rsa_public_key: str):
	public_key_bytes = rsa_public_key.encode("utf-8")
	try:
		return serialization.load_pem_public_key(public_key_bytes)
	except ValueError:
		try:
			wrapped = b"-----BEGIN PUBLIC KEY-----\n" + rsa_public_key.encode("utf-8") + b"\n-----END PUBLIC KEY-----\n"
			return serialization.load_pem_public_key(wrapped)
		except ValueError:
			raise ValueError("Unable to parse RSA public key")


def encrypt_credentials(rsa_public_key: str, plaintext: bytes) -> str:
	public_key = load_rsa_public_key(rsa_public_key)
	encrypted = public_key.encrypt(plaintext, padding.PKCS1v15())
	return encrypted.hex()


def attempt_login(
	session: requests.Session,
	protocol: str,
	host: str,
	document_root: str,
	username: str,
	password: str,
	login_token: str,
	rsa_public_key: str,
	passw_encrypt_enable: str,
	verify: bool,
	verbose: bool,
	debug: bool = False,
) -> bool:
	escaped_username = quote(username, safe="")
	escaped_password = quote(password, safe="")
	login_string = f"user={escaped_username}&password={escaped_password}&ssd=true&token={login_token}&"

	if passw_encrypt_enable == "1":
		if debug or verbose:
			print("req 4. Encrypting login payload with RSA public key")
		credential = encrypt_credentials(rsa_public_key, login_string.encode("utf-8"))
	else:
		credential = login_string

	login_url = build_url(protocol, host, f"/{document_root}/hpe/config/system.xml?action=login&cred={credential[:80]}...")
	if debug:
		print(f"req 4. GET {login_url}")
    
	actual_url = build_url(protocol, host, f"/{document_root}/hpe/config/system.xml?action=login&cred={credential}")
	response = session.get(actual_url, verify=verify, timeout=30)
	response.raise_for_status()
	if debug:
		print(f"req 4. STATUS: {response.status_code}")
    
	status_match = re.search(r"<statusString>(.+?)</statusString>", response.text, re.DOTALL)
	if not status_match:
		raise ValueError("Login response did not contain statusString")

	status = status_match.group(1).strip()
	if debug or verbose:
		print(f"req 4. LOGIN RESPONSE: {status}")
	return status == "OK"


def download_backup(session: requests.Session, protocol: str, host: str, document_root: str, verify: bool, debug: bool = False) -> bytes:
	download_url = build_url(protocol, host, f"/{document_root}/hpe/http_download?action=3&ssd=4")
	if debug:
		print(f"req 5. GET {download_url}")
	response = session.get(download_url, verify=verify, timeout=30)
	response.raise_for_status()
	if debug:
		print(f"req 5. STATUS: {response.status_code}")
		print(f"req 5. CONTENT LENGTH: {len(response.content)} bytes")
	return response.content


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Login to an Aruba Instant On 1930 switch and download the startup configuration."
	)
	parser.add_argument("--ip", required=True, help="Switch IP address or hostname")
	parser.add_argument("--name", required=True, help="Switch name used for logging and fallback filename")
	parser.add_argument("--username", required=True, help="Web UI username")
	parser.add_argument("--password", required=True, help="Web UI password")
	parser.add_argument("--file", default=None, help="Output file path for the downloaded backup")
	parser.add_argument(
		"--protocol",
		choices=["https", "http"],
		default="https",
		help="Preferred protocol for the web UI connection (default: https)",
	)
	parser.add_argument(
		"--allow-insecure",
		action="store_true",
		help="Allow insecure SSL/TLS connections when using HTTPS",
	)
	parser.add_argument(
		"--verbose",
		action="store_true",
		help="Print verbose connection and request details",
	)
	parser.add_argument(
		"--debug",
		action="store_true",
		help="Print detailed debug information including request URLs and response details",
	)
	return parser.parse_args()


def main() -> int:
	args = parse_args()
	output_file = args.file or f"{args.name}.config"
	verify = not args.allow_insecure

	if not verify:
		warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

	session = requests.Session()
	session.headers.update({"User-Agent": "python-requests/aruba-backup"})

	protocols = [args.protocol]
	if args.protocol == "https":
		protocols.append("http")

	login_success = False
	used_protocol = None
	document_root = None

	for protocol in protocols:
		try:
			if args.verbose:
				print(f"Attempting protocol: {protocol.upper()}://{args.ip}")

			document_root, initial_location = get_document_root(session, protocol, args.ip, verify, args.debug)
			if args.verbose and not args.debug:
				print(f"Document root: {document_root}")
				print(f"Initial login location: {initial_location}")

			login_page = fetch_initial_login_page(session, protocol, args.ip, initial_location, verify, args.debug)
			if args.verbose:
				print(f"Initial login page length: {len(login_page)}")

			if "inputUsername" not in login_page and "UserCntrl" not in login_page:
				if args.verbose:
					print("Login page did not include expected Aruba or Cisco login fields.")
				continue

			rsa_public_key, login_token, passw_encrypt_enable = fetch_encryption_settings(session, protocol, args.ip, verify, args.debug)
			if args.verbose and not args.debug:
				print(f"passwEncryptEnable={passw_encrypt_enable}")
				print(f"loginToken={login_token}")

			if attempt_login(
				session,
				protocol,
				args.ip,
				document_root,
				args.username,
				args.password,
				login_token,
				rsa_public_key,
				passw_encrypt_enable,
				verify,
				args.verbose,
				args.debug,
			):
				login_success = True
				used_protocol = protocol
				break
		except SSLError:
			if protocol == "https" and not args.allow_insecure:
				print("HTTPS certificate verification failed. Use --allow-insecure to override.", file=sys.stderr)
				return 1
			if args.verbose:
				print(f"SSL error for {protocol.upper()}://{args.ip}")
		except RequestException as exc:
			if args.verbose:
				print(f"Connection failed for {protocol.upper()}://{args.ip}: {exc}", file=sys.stderr)
		except ValueError as exc:
			if args.verbose:
				print(f"Protocol {protocol.upper()} failed: {exc}", file=sys.stderr)

	if not login_success:
		print("Login failed for both HTTPS and HTTP.", file=sys.stderr)
		return 1

	if args.debug:
		print("\nLOGIN SUCCESSFUL")
	else:
		print(f"Logged in successfully using {used_protocol.upper()} for {args.name} ({args.ip}).")
	if args.verbose and not args.debug:
		print(f"Downloading backup with document root: {document_root}")

	try:
		content = download_backup(session, used_protocol, args.ip, document_root, verify, args.debug)
	except RequestException as exc:
		print(f"Failed to download backup file: {exc}", file=sys.stderr)
		return 1

	output_dir = os.path.dirname(output_file)
	if output_dir:
		os.makedirs(output_dir, exist_ok=True)

	with open(output_file, "wb") as f:
		f.write(content)

	if args.debug:
		print("req 5. DOWNLOAD OK")
		print("END OF SCRIPT, EXITING")
	else:
		print(f"Backup saved to {output_file}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
