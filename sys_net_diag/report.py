"""Report aggregation, formatting (.txt / .json), and file export."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import __version__
from .network_diag import NetworkDiagnosticsReport
from .system_health import SystemHealthReport


@dataclass
class DiagnosticReport:
    """Top-level report combining system health and network diagnostics."""

    tool: str
    version: str
    generated_at_utc: str
    overall_status: str
    system_health: Optional[SystemHealthReport] = None
    network_diagnostics: Optional[NetworkDiagnosticsReport] = None


def format_bytes(num_bytes: int) -> str:
    """Format byte counts into human-readable units."""
    value = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024.0 or unit == "PB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{num_bytes} B"


def compute_overall_status(
    system_health: Optional[SystemHealthReport],
    network_diagnostics: Optional[NetworkDiagnosticsReport],
) -> str:
    """Compute unified overall status across executed diagnostic suites."""
    statuses: list[str] = []
    if system_health is not None:
        statuses.append(system_health.overall_status)
    if network_diagnostics is not None:
        statuses.append(network_diagnostics.overall_status)

    if not statuses:
        return "UNKNOWN"
    if "CRIT" in statuses:
        return "CRIT"
    if "FAIL" in statuses:
        return "FAIL"
    if "WARN" in statuses:
        return "WARN"
    return "OK"


def build_report(
    system_health: Optional[SystemHealthReport] = None,
    network_diagnostics: Optional[NetworkDiagnosticsReport] = None,
) -> DiagnosticReport:
    """Construct a DiagnosticReport with a UTC timestamp and overall status."""
    return DiagnosticReport(
        tool="sys-net-diag",
        version=__version__,
        generated_at_utc=datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        overall_status=compute_overall_status(system_health, network_diagnostics),
        system_health=system_health,
        network_diagnostics=network_diagnostics,
    )


def report_to_dict(report: DiagnosticReport) -> dict[str, Any]:
    """Convert a DiagnosticReport into a JSON-serializable dictionary."""
    return asdict(report)


def format_report_json(report: DiagnosticReport) -> str:
    """Serialize a DiagnosticReport to formatted JSON."""
    return json.dumps(report_to_dict(report), indent=2)


def format_report_text(report: DiagnosticReport) -> str:
    """Render a DiagnosticReport as a clean human-readable plain-text report."""
    sep = "=" * 72
    subsep = "-" * 72
    lines: list[str] = [
        sep,
        f"  {report.tool} v{report.version} - L1 IT Support & Network Diagnostic Report",
        sep,
        f"Generated (UTC) : {report.generated_at_utc}",
        f"Overall Status  : {report.overall_status}",
    ]

    findings: list[str] = []

    if report.system_health is not None:
        sys_h = report.system_health
        lines.extend(
            [
                "",
                "[SYSTEM HEALTH]",
                subsep,
                f"Status          : {sys_h.overall_status}",
                f"Hostname        : {sys_h.hostname}",
                f"OS              : {sys_h.os_name} {sys_h.os_release} ({sys_h.architecture})",
                f"Python          : {sys_h.python_version}",
                f"Boot Time (UTC) : {sys_h.uptime.boot_time_utc}",
                f"Uptime          : {sys_h.uptime.uptime_human}",
            ]
        )

        load_str = (
            f" | Load Avg (1/5/15m): {sys_h.cpu.load_avg[0]}, {sys_h.cpu.load_avg[1]}, {sys_h.cpu.load_avg[2]}"
            if sys_h.cpu.load_avg is not None
            else ""
        )
        lines.append(
            f"CPU             : {sys_h.cpu.usage_percent}% [{sys_h.cpu.status}] "
            f"(Cores: {sys_h.cpu.physical_cores or '?'} physical / {sys_h.cpu.logical_cores or '?'} logical){load_str}"
        )

        mem = sys_h.memory
        lines.append(
            f"Memory (RAM)    : {format_bytes(mem.used_bytes)} / {format_bytes(mem.total_bytes)} "
            f"({mem.usage_percent}%) [{mem.status}] | Available: {format_bytes(mem.available_bytes)}"
        )
        if mem.swap_total_bytes > 0:
            lines.append(
                f"Swap            : {format_bytes(mem.swap_used_bytes)} / {format_bytes(mem.swap_total_bytes)} "
                f"({mem.swap_percent}%)"
            )

        lines.append("Disks           :")
        if sys_h.disks:
            for disk in sys_h.disks:
                lines.append(
                    f"  - {disk.mountpoint} ({disk.fstype}): "
                    f"{format_bytes(disk.used_bytes)} / {format_bytes(disk.total_bytes)} "
                    f"({disk.usage_percent}% used, {format_bytes(disk.free_bytes)} free) [{disk.status}]"
                )
        else:
            lines.append("  - No accessible disk partitions found.")

        findings.extend(sys_h.warnings)

    if report.network_diagnostics is not None:
        net = report.network_diagnostics
        loc = net.local_network
        lines.extend(
            [
                "",
                "[NETWORK DIAGNOSTICS]",
                subsep,
                f"Status          : {net.overall_status}",
                f"Primary Local IP: {loc.primary_ip or 'Not detected'}",
                f"Default Gateway : {loc.default_gateway or 'Not detected'}"
                + (f" (via {loc.gateway_detection_method})" if loc.gateway_detection_method else ""),
            ]
        )

        if loc.interfaces:
            lines.append("Interfaces      :")
            for iface in loc.interfaces:
                state = "UP" if iface.is_up else "DOWN"
                addrs = ", ".join(iface.ipv4 + iface.ipv6[:1])
                mac_part = f" | MAC: {iface.mac}" if iface.mac else ""
                lines.append(f"  - {iface.name} [{state}]: {addrs}{mac_part}")

        lines.append("DNS Resolution  :")
        for dns in net.dns_checks:
            if dns.resolved:
                ips = ", ".join(dns.ip_addresses)
                lines.append(f"  - {dns.hostname}: {ips} ({dns.latency_ms} ms) [{dns.status}]")
            else:
                lines.append(f"  - {dns.hostname}: FAILED ({dns.error}) [{dns.status}]")

        lines.append("ICMP Ping       :")
        for ping in net.ping_checks:
            if ping.reachable:
                rtt = (
                    f"min/avg/max={ping.min_ms}/{ping.avg_ms}/{ping.max_ms} ms"
                    if ping.avg_ms is not None
                    else "RTT n/a"
                )
                lines.append(
                    f"  - {ping.target}: {ping.packets_received}/{ping.packets_sent} received, "
                    f"{ping.packet_loss_percent}% loss, {rtt} [{ping.status}]"
                )
            else:
                lines.append(
                    f"  - {ping.target}: UNREACHABLE ({ping.packet_loss_percent}% loss, {ping.error}) [{ping.status}]"
                )

        if net.port_checks:
            lines.append("TCP Port Checks :")
            for port_res in net.port_checks:
                if port_res.is_open:
                    lines.append(
                        f"  - {port_res.host}:{port_res.port} ({port_res.service}): "
                        f"OPEN ({port_res.latency_ms} ms)"
                    )
                else:
                    lines.append(
                        f"  - {port_res.host}:{port_res.port} ({port_res.service}): "
                        f"CLOSED ({port_res.error})"
                    )

        findings.extend(net.issues)

    lines.extend(["", "[L1 TRIAGE SUMMARY]", subsep])
    if findings:
        for item in findings:
            lines.append(f"  * {item}")
    else:
        lines.append("  * All executed checks completed with no warnings or failures.")
    lines.append(sep)
    return "\n".join(lines)


def _resolve_export_format(output_path: Path, fmt: Optional[str]) -> str:
    if fmt:
        normalized = fmt.strip().lower()
        if normalized in ("txt", "text"):
            return "txt"
        if normalized == "json":
            return "json"
        raise ValueError(f"Unsupported export format: {fmt!r}. Expected 'txt' or 'json'.")

    suffix = output_path.suffix.lower()
    if suffix == ".txt":
        return "txt"
    if suffix == ".json":
        return "json"
    raise ValueError(
        f"Cannot infer export format from '{output_path.name}'. "
        "Use a .txt or .json extension, or pass --export-format."
    )


def export_report(
    report: DiagnosticReport,
    output_path: str | Path,
    fmt: Optional[str] = None,
) -> tuple[Path, str]:
    """Write the diagnostic report to disk as .txt or .json."""
    path = Path(output_path)
    resolved_fmt = _resolve_export_format(path, fmt)
    content = format_report_json(report) if resolved_fmt == "json" else format_report_text(report)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8")
    return path, resolved_fmt
