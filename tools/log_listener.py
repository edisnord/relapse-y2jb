#!/usr/bin/env python3
"""Capture Relapse/Y2JB UDP mirror datagrams without recording sender addresses."""

from __future__ import annotations

import argparse
import socket
import sys
from datetime import datetime
from pathlib import Path


MAX_DATAGRAM_SIZE = 65_535


def parse_port(value: str) -> int:
    """Parse a UDP port number in the valid IPv4 port range."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def capture(output: Path | None, host: str, port: int) -> int:
    """Write received UDP datagrams byte-for-byte to a new file until Ctrl+C."""
    if output is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        output = Path(f"relapse-udp-{stamp}.log")
    packets = 0
    byte_count = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind((host, port))
            with output.open("xb") as destination:
                print(
                    f"Listening on {host}:{port}; saving to {output}. "
                    "Send the payload now. Press Ctrl+C to stop."
                )
                try:
                    while True:
                        payload, _sender = listener.recvfrom(MAX_DATAGRAM_SIZE)
                        destination.write(payload)
                        destination.flush()
                        packets += 1
                        byte_count += len(payload)
                        print(
                            f"\rCaptured {packets} datagrams ({byte_count} bytes)",
                            end="",
                            flush=True,
                        )
                except KeyboardInterrupt:
                    print()
                    print(f"Saved {packets} datagrams ({byte_count} bytes) to {output}")
    except OSError as exc:
        print(f"error: capture failed: {exc}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    """Parse capture options and start the local UDP listener."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="new capture file path; defaults to a unique timestamped filename",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="local IPv4 address to bind (default: all interfaces)",
    )
    parser.add_argument("--port", type=parse_port, default=5050, help="UDP port (default: 5050)")
    args = parser.parse_args()
    return capture(args.output, args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
