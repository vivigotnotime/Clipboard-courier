"""Command-line interface for the Courier CA.

    python -m ca init [--dir ca-data] --name "Courier Demo CA" [--days 730]
    python -m ca fingerprint [--dir ca-data]

Run this on the admin's machine, never on the relay.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from ca.authority import CA_VALIDITY_DAYS, init_ca, load_ca_certificate
from courier.errors import CourierError
from courier.pki.certs import fingerprint, format_fingerprint
from courier.storage.keystore import MIN_PASSPHRASE_LENGTH

DEFAULT_DIR = Path("ca-data")


def _new_passphrase() -> bytes:
    first = getpass.getpass("New CA passphrase: ").encode()
    if len(first) < MIN_PASSPHRASE_LENGTH:
        raise CourierError(f"passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")
    if getpass.getpass("Repeat CA passphrase: ").encode() != first:
        raise CourierError("passphrases do not match")
    return first


def _print_fingerprint(cert) -> None:
    print("CA fingerprint (SHA-256):")
    print("  " + format_fingerprint(fingerprint(cert)))


def cmd_init(args: argparse.Namespace) -> None:
    passphrase = _new_passphrase()
    print("Generating RSA-3072 CA key...")
    cert = init_ca(args.dir, args.name, passphrase, validity_days=args.days)
    print(f"CA created in {args.dir}/ (key: ca.key, certificate: ca.crt)")
    print(f"Valid until {cert.not_valid_after_utc:%Y-%m-%d %H:%M} UTC")
    _print_fingerprint(cert)
    print("Keep the passphrase safe. Read this fingerprint out when enrolling devices.")


def cmd_fingerprint(args: argparse.Namespace) -> None:
    _print_fingerprint(load_ca_certificate(args.dir))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ca", description="Clipboard Courier CA tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create a new CA key and certificate")
    p_init.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="CA directory")
    p_init.add_argument("--name", required=True, help='CA name, e.g. "Courier Demo CA"')
    p_init.add_argument("--days", type=int, default=CA_VALIDITY_DAYS, help="validity in days")
    p_init.set_defaults(func=cmd_init)

    p_fp = sub.add_parser("fingerprint", help="print the CA certificate fingerprint")
    p_fp.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="CA directory")
    p_fp.set_defaults(func=cmd_fingerprint)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except CourierError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):     # Ctrl+D or Ctrl+C at a prompt
        print("\ncancelled", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
