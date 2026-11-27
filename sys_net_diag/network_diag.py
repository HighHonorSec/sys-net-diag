"""Cross-platform network diagnostics for L1 IT support troubleshooting."""

from __future__ import annotations

import os
import platform
import re
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

import psutil

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


@dataclass
class DnsCheckResult:
    """Result of resolving a hostname via DNS."""

    hostname: str
    resolved: bool
    ip_addresses: list[str]
    latency_ms: Optional[float]
    status: str
    error: Optional[str] = None


@dataclass
class PingResult:
    """Result of an ICMP ping probe."""

    target: str
    reachable: bool
    packets_sent: int
    packets_received: int
    packet_loss_percent: float
    min_ms: Optional[float]
    avg_ms: Optional[float]
    max_ms: Optional[float]
    status: str
    error: Optional[str] = None


@dataclass
class InterfaceInfo:
    """Network interface address and link state summary."""

    name: str
    is_up: bool
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    mac: Optional[str] = None


@dataclass
class LocalNetworkInfo:
    """Local IP, default gateway, and interface summary."""

    primary_ip: Optional[str]
    default_gateway: Optional[str]
    interfaces: list[InterfaceInfo]
    gateway_detection_method: Optional[str]
    status: str
    error: Optional[str] = None


@dataclass
class PortCheckResult:
    """Result of a TCP port connectivity check."""

    host: str
    port: int
    service: str
    is_open: bool
    latency_ms: Optional[float]
    status: str
    error: Optional[str] = None


@dataclass
class NetworkDiagnosticsReport:
    """Aggregated network diagnostics report."""

    local_network: LocalNetworkInfo
    dns_checks: list[DnsCheckResult]
    ping_checks: list[PingResult]
    port_checks: list[PortCheckResult]
    overall_status: str
    issues: list[str] = field(default_factory=list)


def check_dns(hostname: str) -> DnsCheckResult:
    """Resolve a hostname using the system resolver and measure latency."""
    host = hostname.strip()
    if not host:
        return DnsCheckResult(
            hostname=hostname,
            resolved=False,
            ip_addresses=[],
            latency_ms=None,
            status="FAIL",
            error="Empty hostname provided",
        )

    start = time.perf_counter()
    try:
        addr_info = socket.getaddrinfo(host, None)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        ips: list[str] = []
        for entry in addr_info:
            ip = entry[4][0]
            if ip not in ips:
                ips.append(ip)
        return DnsCheckResult(
            hostname=host,
            resolved=bool(ips),
            ip_addresses=ips,
            latency_ms=elapsed_ms,
            status="OK" if ips else "FAIL",
            error=None if ips else "No IP addresses returned",
        )
    except (socket.gaierror, OSError) as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return DnsCheckResult(
            hostname=host,
            resolved=False,
            ip_addresses=[],
            latency_ms=elapsed_ms,
            status="FAIL",
            error=str(exc),
        )


def _build_ping_command(target: str, count: int, timeout: float, system_name: str) -> list[str]:
    system_lower = system_name.lower()
    if system_lower == "windows":
        timeout_ms = max(500, int(timeout * 1000))
        return ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    if system_lower == "darwin":
        timeout_ms = max(500, int(timeout * 1000))
        return ["ping", "-c", str(count), "-W", str(timeout_ms), target]
    timeout_sec = max(1, int(round(timeout)))
    return ["ping", "-c", str(count), "-W", str(timeout_sec), target]


def _parse_ping_output(
    output: str,
    target: str,
    requested_count: int,
    returncode: int,
) -> PingResult:
    sent = requested_count
    received = 0
    loss_pct = 100.0
    min_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    max_ms: Optional[float] = None

    # Windows summary: Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
    win_pkt = re.search(
        r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*\d+\s*\((\d+)%\s*loss\)",
        output,
        re.IGNORECASE,
    )
    # POSIX summary: 4 packets transmitted, 4 received, 0% packet loss
    posix_pkt = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received,\s+([0-9.]+)%\s+packet loss",
        output,
        re.IGNORECASE,
    )

    if win_pkt:
        sent = int(win_pkt.group(1))
        received = int(win_pkt.group(2))
        loss_pct = float(win_pkt.group(3))
    elif posix_pkt:
        sent = int(posix_pkt.group(1))
        received = int(posix_pkt.group(2))
        loss_pct = float(posix_pkt.group(3))

    # Windows RTT: Minimum = 12ms, Maximum = 18ms, Average = 14ms
    win_rtt = re.search(
        r"Minimum\s*=\s*([0-9.]+)\s*ms,\s*Maximum\s*=\s*([0-9.]+)\s*ms,\s*Average\s*=\s*([0-9.]+)\s*ms",
        output,
        re.IGNORECASE,
    )
    # POSIX RTT: rtt min/avg/max/mdev = 10.123/12.456/15.789/1.234 ms
    posix_rtt = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/[0-9.]+\s*ms",
        output,
        re.IGNORECASE,
    )

    if win_rtt:
        min_ms = round(float(win_rtt.group(1)), 2)
        max_ms = round(float(win_rtt.group(2)), 2)
        avg_ms = round(float(win_rtt.group(3)), 2)
    elif posix_rtt:
        min_ms = round(float(posix_rtt.group(1)), 2)
        avg_ms = round(float(posix_rtt.group(2)), 2)
        max_ms = round(float(posix_rtt.group(3)), 2)
    else:
        # Fallback: extract per-packet times like time=12.4 ms or time<1ms
        times: list[float] = []
        for match in re.finditer(r"time\s*([<=])\s*([0-9.]+)\s*ms", output, re.IGNORECASE):
            val = float(match.group(2))
            times.append(0.5 if match.group(1) == "<" else val)
        if times:
            min_ms = round(min(times), 2)
            max_ms = round(max(times), 2)
            avg_ms = round(sum(times) / len(times), 2)
            if not win_pkt and not posix_pkt:
                received = len(times)
                loss_pct = round(((sent - received) / sent) * 100.0, 1) if sent else 100.0

    reachable = received > 0 or (returncode == 0 and avg_ms is not None)
    if not reachable:
        status = "FAIL"
    elif loss_pct > 0.0 or (avg_ms is not None and avg_ms > 150.0):
        status = "WARN"
    else:
        status = "OK"

    error = None
    if not reachable:
        error = f"Host unreachable (100% packet loss, exit code {returncode})"

    return PingResult(
        target=target,
        reachable=reachable,
        packets_sent=sent,
        packets_received=received,
        packet_loss_percent=round(loss_pct, 1),
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        status=status,
        error=error,
    )


def ping_host(target: str, count: int = 4, timeout: float = 3.0) -> PingResult:
    """Measure ICMP ping latency and packet loss to a target host."""
    host = target.strip()
    if not host:
        return PingResult(
            target=target,
            reachable=False,
            packets_sent=0,
            packets_received=0,
            packet_loss_percent=100.0,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            status="FAIL",
            error="Empty ping target provided",
        )

    cmd = _build_ping_command(host, count=max(1, count), timeout=timeout, system_name=platform.system())
    total_timeout = max(timeout * count + 3.0, 5.0)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=total_timeout,
            check=False,
        )
        combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
        return _parse_ping_output(combined, target=host, requested_count=count, returncode=proc.returncode)
    except subprocess.TimeoutExpired:
        return PingResult(
            target=host,
            reachable=False,
            packets_sent=count,
            packets_received=0,
            packet_loss_percent=100.0,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            status="FAIL",
            error=f"Ping command timed out after {total_timeout:.1f}s",
        )
    except FileNotFoundError:
        return PingResult(
            target=host,
            reachable=False,
            packets_sent=count,
            packets_received=0,
            packet_loss_percent=100.0,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            status="FAIL",
            error="System 'ping' command not found",
        )
    except OSError as exc:
        return PingResult(
            target=host,
            reachable=False,
            packets_sent=count,
            packets_received=0,
            packet_loss_percent=100.0,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            status="FAIL",
            error=str(exc),
        )


def detect_primary_ip() -> Optional[str]:
    """Detect the primary outbound local IPv4 address without sending network traffic."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    try:
        fallback_ip = socket.gethostbyname(socket.gethostname())
        if fallback_ip and not fallback_ip.startswith("127."):
            return fallback_ip
    except OSError:
        pass
    return None


def _parse_proc_net_route(content: str) -> Optional[str]:
    """Parse Linux /proc/net/route text to extract the IPv4 default gateway."""
    for line in content.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        destination_hex, gateway_hex, flags_hex = parts[1], parts[2], parts[3]
        if destination_hex != "00000000":
            continue
        try:
            flags = int(flags_hex, 16)
            if not (flags & 0x2):
                continue
            packed = struct.pack("=I", int(gateway_hex, 16))
            gw_ip = socket.inet_ntoa(packed)
            if gw_ip != "0.0.0.0":
                return gw_ip
        except (ValueError, struct.error, OSError):
            continue
    return None


def _parse_windows_route_print(output: str) -> Optional[str]:
    """Parse `route print 0.0.0.0` output on Windows for the default gateway."""
    for line in output.splitlines():
        match = re.match(
            r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+",
            line,
        )
        if match:
            return match.group(1)
    return None


def _parse_ip_route_default(output: str) -> Optional[str]:
    """Parse `ip route show default` output on Linux."""
    match = re.search(r"\bdefault\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})\b", output)
    return match.group(1) if match else None


def _parse_macos_route_get(output: str) -> Optional[str]:
    """Parse `route -n get default` output on macOS."""
    match = re.search(r"^\s*gateway:\s*(\S+)", output, re.MULTILINE)
    return match.group(1) if match else None


def detect_default_gateway() -> tuple[Optional[str], Optional[str]]:
    """Detect the default IPv4 gateway across Windows, Linux, and macOS."""
    system = platform.system().lower()

    if system == "windows":
        try:
            proc = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            gw = _parse_windows_route_print(proc.stdout)
            if gw:
                return gw, "route print"
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None, None

    if system == "linux":
        proc_route = "/proc/net/route"
        if os.path.exists(proc_route):
            try:
                with open(proc_route, "r", encoding="utf-8") as fh:
                    gw = _parse_proc_net_route(fh.read())
                if gw:
                    return gw, "/proc/net/route"
            except OSError:
                pass
        try:
            proc = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            gw = _parse_ip_route_default(proc.stdout)
            if gw:
                return gw, "ip route"
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None, None

    if system == "darwin":
        try:
            proc = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            gw = _parse_macos_route_get(proc.stdout)
            if gw:
                return gw, "route get default"
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None, None

    return None, None


def get_local_network_info() -> LocalNetworkInfo:
    """Gather local primary IP, default gateway, and interface inventory."""
    primary_ip = detect_primary_ip()
    gateway, method = detect_default_gateway()

    interfaces: list[InterfaceInfo] = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            is_up = bool(stats[name].isup) if name in stats else False
            ipv4s: list[str] = []
            ipv6s: list[str] = []
            mac: Optional[str] = None
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address:
                    ipv4s.append(addr.address)
                elif addr.family == socket.AF_INET6 and addr.address:
                    ipv6s.append(addr.address.split("%")[0])
                elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK and addr.address:
                    mac = addr.address
            if ipv4s or ipv6s:
                interfaces.append(
                    InterfaceInfo(
                        name=name,
                        is_up=is_up,
                        ipv4=ipv4s,
                        ipv6=ipv6s,
                        mac=mac,
                    )
                )
    except OSError as exc:
        return LocalNetworkInfo(
            primary_ip=primary_ip,
            default_gateway=gateway,
            interfaces=[],
            gateway_detection_method=method,
            status="WARN",
            error=str(exc),
        )

    if primary_ip is None and interfaces:
        for iface in interfaces:
            if iface.is_up:
                for ip in iface.ipv4:
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        primary_ip = ip
                        break
            if primary_ip:
                break

    if primary_ip and gateway:
        status = "OK"
    elif primary_ip or gateway:
        status = "WARN"
    else:
        status = "FAIL"

    return LocalNetworkInfo(
        primary_ip=primary_ip,
        default_gateway=gateway,
        interfaces=interfaces,
        gateway_detection_method=method,
        status=status,
    )


def check_port(host: str, port: int, timeout: float = 3.0) -> PortCheckResult:
    """Check whether a TCP port on a host is reachable and measure connect latency."""
    service = COMMON_PORTS.get(port, "Custom")
    target_host = host.strip()
    if not target_host or not (1 <= port <= 65535):
        return PortCheckResult(
            host=host,
            port=port,
            service=service,
            is_open=False,
            latency_ms=None,
            status="CLOSED",
            error="Invalid host or port number (must be 1-65535)",
        )

    start = time.perf_counter()
    try:
        with socket.create_connection((target_host, port), timeout=timeout):
            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return PortCheckResult(
                host=target_host,
                port=port,
                service=service,
                is_open=True,
                latency_ms=elapsed_ms,
                status="OPEN",
            )
    except (socket.timeout, TimeoutError):
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return PortCheckResult(
            host=target_host,
            port=port,
            service=service,
            is_open=False,
            latency_ms=elapsed_ms,
            status="CLOSED",
            error=f"Connection timed out after {timeout:.1f}s",
        )
    except (ConnectionRefusedError, socket.gaierror, OSError) as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return PortCheckResult(
            host=target_host,
            port=port,
            service=service,
            is_open=False,
            latency_ms=elapsed_ms,
            status="CLOSED",
            error=str(exc),
        )


def collect_network_diagnostics(
    dns_hosts: Optional[list[str]] = None,
    ping_hosts: Optional[list[str]] = None,
    ping_count: int = 4,
    port_host: Optional[str] = "google.com",
    ports: Optional[list[int]] = None,
    timeout: float = 3.0,
) -> NetworkDiagnosticsReport:
    """Run local network detection, DNS resolution, ICMP ping, and port checks."""
    local_net = get_local_network_info()

    dns_targets = dns_hosts if dns_hosts is not None else ["google.com"]
    ping_targets = ping_hosts if ping_hosts is not None else ["8.8.8.8"]
    port_targets = ports if ports is not None else [80, 443]

    dns_results = [check_dns(h) for h in dns_targets]
    ping_results = [ping_host(h, count=ping_count, timeout=timeout) for h in ping_targets]
    port_results = (
        [check_port(port_host, p, timeout=timeout) for p in port_targets]
        if port_host and port_targets
        else []
    )

    issues: list[str] = []
    if local_net.status != "OK":
        if not local_net.primary_ip:
            issues.append("No active non-loopback local IPv4 address detected")
        if not local_net.default_gateway:
            issues.append("Default gateway could not be detected")

    for dns_res in dns_results:
        if not dns_res.resolved:
            issues.append(f"DNS resolution failed for {dns_res.hostname}: {dns_res.error}")

    for ping_res in ping_results:
        if not ping_res.reachable:
            issues.append(f"Ping failed for {ping_res.target}: {ping_res.error}")
        elif ping_res.status == "WARN":
            issues.append(
                f"Degraded ping to {ping_res.target}: loss={ping_res.packet_loss_percent}%, avg={ping_res.avg_ms}ms"
            )

    for port_res in port_results:
        if not port_res.is_open:
            issues.append(
                f"Port {port_res.port}/{port_res.service} closed on {port_res.host}: {port_res.error}"
            )

    has_fail = (
        local_net.status == "FAIL"
        or any(d.status == "FAIL" for d in dns_results)
        or any(p.status == "FAIL" for p in ping_results)
    )
    has_warn = (
        local_net.status == "WARN"
        or any(p.status == "WARN" for p in ping_results)
        or any(not pt.is_open for pt in port_results)
    )

    if has_fail:
        overall = "FAIL"
    elif has_warn:
        overall = "WARN"
    else:
        overall = "OK"

    return NetworkDiagnosticsReport(
        local_network=local_net,
        dns_checks=dns_results,
        ping_checks=ping_results,
        port_checks=port_results,
        overall_status=overall,
        issues=issues,
    )
