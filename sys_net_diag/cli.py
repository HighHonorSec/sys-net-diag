"""Argparse CLI entrypoint for sys-net-diag."""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from . import __version__
from .network_diag import collect_network_diagnostics
from .report import build_report, export_report, format_report_json, format_report_text
from .system_health import collect_system_health


def parse_ports(raw_values: Sequence[str]) -> list[int]:
    """Parse space- or comma-separated TCP ports and validate range 1-65535."""
    ports: list[int] = []
    for item in raw_values:
        for token in item.split(","):
            stripped = token.strip()
            if not stripped:
                continue
            try:
                port = int(stripped)
            except ValueError as exc:
                raise ValueError(f"Invalid port number: {stripped!r}") from exc
            if not (1 <= port <= 65535):
                raise ValueError(f"Port number out of range (1-65535): {port}")
            if port not in ports:
                ports.append(port)
    if not ports:
        raise ValueError("At least one valid TCP port must be specified.")
    return ports


def parse_hosts(raw_values: Sequence[str]) -> list[str]:
    """Parse space- or comma-separated hostnames or IP addresses."""
    hosts: list[str] = []
    for item in raw_values:
        for token in item.split(","):
            stripped = token.strip()
            if stripped and stripped not in hosts:
                hosts.append(stripped)
    return hosts


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="sys-net-diag",
        description=(
            "Cross-platform L1 IT Support & Network Troubleshooting CLI. "
            "Collects CPU/RAM/Disk/Uptime health and DNS/ICMP/Gateway/TCP port diagnostics."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    sys_group = parser.add_argument_group("System Health Options")
    sys_group.add_argument(
        "--skip-system",
        action="store_true",
        help="Skip system health checks (CPU, RAM, Disk, Uptime).",
    )
    sys_group.add_argument(
        "--cpu-interval",
        type=float,
        default=0.2,
        help="Sampling interval in seconds for CPU percentage (default: 0.2).",
    )
    sys_group.add_argument(
        "--disk-path",
        type=str,
        default=None,
        help="Specific filesystem path or drive to check instead of all partitions.",
    )

    net_group = parser.add_argument_group("Network Diagnostics Options")
    net_group.add_argument(
        "--skip-network",
        action="store_true",
        help="Skip network diagnostics (Local IP/Gateway, DNS, Ping, Ports).",
    )
    net_group.add_argument(
        "--dns-host",
        nargs="+",
        default=["google.com"],
        metavar="HOST",
        help="Hostname(s) to resolve via DNS (default: google.com).",
    )
    net_group.add_argument(
        "--ping-host",
        nargs="+",
        default=["8.8.8.8"],
        metavar="HOST",
        help="Host(s) or IP(s) to ping via ICMP (default: 8.8.8.8).",
    )
    net_group.add_argument(
        "--ping-count",
        type=int,
        default=4,
        help="Number of ICMP echo requests per host (default: 4).",
    )
    net_group.add_argument(
        "--port-host",
        type=str,
        default="google.com",
        help="Target host for TCP port connectivity checks (default: google.com).",
    )
    net_group.add_argument(
        "--ports",
        nargs="+",
        default=["80", "443"],
        metavar="PORT",
        help="TCP port(s) to check, space- or comma-separated (default: 80 443).",
    )
    net_group.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Timeout in seconds for ping and TCP port checks (default: 3.0).",
    )

    out_group = parser.add_argument_group("Output & Export Options")
    out_group.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="Console output format (default: text).",
    )
    out_group.add_argument(
        "-o",
        "--export",
        type=str,
        default=None,
        metavar="PATH",
        help="Export diagnostic report to a .txt or .json file.",
    )
    out_group.add_argument(
        "--export-format",
        choices=("txt", "json"),
        default=None,
        help="Explicitly set export format (overrides file extension inference).",
    )
    out_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress report output on stdout (useful with --export).",
    )
    out_group.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 if overall status is not OK.",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the sys-net-diag CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.skip_system and args.skip_network:
        parser.error("Cannot specify both --skip-system and --skip-network.")

    if args.cpu_interval < 0:
        parser.error("--cpu-interval must be >= 0.")
    if args.ping_count < 1:
        parser.error("--ping-count must be >= 1.")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0.")

    dns_hosts: list[str] = []
    ping_hosts: list[str] = []
    ports: list[int] = []
    if not args.skip_network:
        dns_hosts = parse_hosts(args.dns_host)
        ping_hosts = parse_hosts(args.ping_host)
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            parser.error(str(exc))

    system_report = (
        None
        if args.skip_system
        else collect_system_health(cpu_interval=args.cpu_interval, disk_path=args.disk_path)
    )
    network_report = (
        None
        if args.skip_network
        else collect_network_diagnostics(
            dns_hosts=dns_hosts,
            ping_hosts=ping_hosts,
            ping_count=args.ping_count,
            port_host=args.port_host,
            ports=ports,
            timeout=args.timeout,
        )
    )

    report = build_report(system_health=system_report, network_diagnostics=network_report)

    if not args.quiet:
        rendered = (
            format_report_json(report)
            if args.output_format == "json"
            else format_report_text(report)
        )
        print(rendered)

    if args.export:
        try:
            exported_path, resolved_fmt = export_report(
                report, output_path=args.export, fmt=args.export_format
            )
            if not args.quiet:
                notice_stream = sys.stderr if args.output_format == "json" else sys.stdout
                print(f"Report exported ({resolved_fmt}) to: {exported_path}", file=notice_stream)
        except (ValueError, OSError) as exc:
            print(f"Error exporting report: {exc}", file=sys.stderr)
            return 2

    if args.strict and report.overall_status != "OK":
        return 1
    return 0
