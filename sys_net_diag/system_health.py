"""Cross-platform system health diagnostics powered by psutil."""

from __future__ import annotations

import platform
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import psutil


@dataclass
class CpuInfo:
    """CPU utilization and core metrics."""

    usage_percent: float
    physical_cores: Optional[int]
    logical_cores: Optional[int]
    load_avg: Optional[tuple[float, float, float]]
    status: str


@dataclass
class MemoryInfo:
    """RAM and swap utilization metrics."""

    total_bytes: int
    available_bytes: int
    used_bytes: int
    usage_percent: float
    swap_total_bytes: int
    swap_used_bytes: int
    swap_percent: float
    status: str


@dataclass
class DiskPartitionInfo:
    """Disk space metrics for a single partition or path."""

    device: str
    mountpoint: str
    fstype: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    usage_percent: float
    status: str


@dataclass
class UptimeInfo:
    """Operating system boot time and uptime."""

    boot_time_utc: str
    uptime_seconds: float
    uptime_human: str


@dataclass
class SystemHealthReport:
    """Aggregated system health snapshot."""

    hostname: str
    os_name: str
    os_release: str
    os_version: str
    architecture: str
    python_version: str
    cpu: CpuInfo
    memory: MemoryInfo
    disks: list[DiskPartitionInfo]
    uptime: UptimeInfo
    overall_status: str
    warnings: list[str] = field(default_factory=list)


_IGNORED_FSTYPES = {"squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs"}


def _evaluate_threshold(percent: float, warn_at: float, crit_at: float) -> str:
    if percent >= crit_at:
        return "CRIT"
    if percent >= warn_at:
        return "WARN"
    return "OK"


def format_uptime(seconds: float) -> str:
    """Convert elapsed seconds into a human-readable duration string."""
    total = max(0, int(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def get_cpu_info(interval: float = 0.2) -> CpuInfo:
    """Collect CPU usage, core counts, and load averages where supported."""
    usage = float(psutil.cpu_percent(interval=interval))
    physical = psutil.cpu_count(logical=False)
    logical = psutil.cpu_count(logical=True)

    load_avg: Optional[tuple[float, float, float]] = None
    try:
        raw_load = psutil.getloadavg()
        load_avg = (round(raw_load[0], 2), round(raw_load[1], 2), round(raw_load[2], 2))
    except (AttributeError, OSError, RuntimeError, NotImplementedError):
        load_avg = None

    return CpuInfo(
        usage_percent=round(usage, 1),
        physical_cores=physical,
        logical_cores=logical,
        load_avg=load_avg,
        status=_evaluate_threshold(usage, warn_at=80.0, crit_at=95.0),
    )


def get_memory_info() -> MemoryInfo:
    """Collect virtual memory and swap utilization."""
    vm = psutil.virtual_memory()
    try:
        swap = psutil.swap_memory()
        swap_total = int(swap.total)
        swap_used = int(swap.used)
        swap_pct = round(float(swap.percent), 1)
    except (OSError, RuntimeError):
        swap_total = 0
        swap_used = 0
        swap_pct = 0.0

    usage_pct = round(float(vm.percent), 1)
    return MemoryInfo(
        total_bytes=int(vm.total),
        available_bytes=int(vm.available),
        used_bytes=int(vm.used),
        usage_percent=usage_pct,
        swap_total_bytes=swap_total,
        swap_used_bytes=swap_used,
        swap_percent=swap_pct,
        status=_evaluate_threshold(usage_pct, warn_at=80.0, crit_at=95.0),
    )


def get_disk_info(disk_path: Optional[str] = None) -> list[DiskPartitionInfo]:
    """Collect disk usage for a specific path or all accessible local partitions."""
    results: list[DiskPartitionInfo] = []

    if disk_path:
        usage = psutil.disk_usage(disk_path)
        pct = round(float(usage.percent), 1)
        results.append(
            DiskPartitionInfo(
                device=disk_path,
                mountpoint=disk_path,
                fstype="custom",
                total_bytes=int(usage.total),
                used_bytes=int(usage.used),
                free_bytes=int(usage.free),
                usage_percent=pct,
                status=_evaluate_threshold(pct, warn_at=85.0, crit_at=95.0),
            )
        )
        return results

    seen_mounts: set[str] = set()
    for part in psutil.disk_partitions(all=False):
        opts = {opt.strip().lower() for opt in (part.opts or "").split(",") if opt.strip()}
        if "cdrom" in opts or not part.fstype:
            continue
        if part.fstype.lower() in _IGNORED_FSTYPES:
            continue
        if part.mountpoint in seen_mounts:
            continue
        seen_mounts.add(part.mountpoint)

        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue

        pct = round(float(usage.percent), 1)
        results.append(
            DiskPartitionInfo(
                device=part.device,
                mountpoint=part.mountpoint,
                fstype=part.fstype,
                total_bytes=int(usage.total),
                used_bytes=int(usage.used),
                free_bytes=int(usage.free),
                usage_percent=pct,
                status=_evaluate_threshold(pct, warn_at=85.0, crit_at=95.0),
            )
        )
    return results


def get_uptime_info() -> UptimeInfo:
    """Collect OS boot timestamp and elapsed uptime."""
    boot_ts = float(psutil.boot_time())
    uptime_secs = max(0.0, time.time() - boot_ts)
    boot_dt = datetime.fromtimestamp(boot_ts, tz=timezone.utc)
    return UptimeInfo(
        boot_time_utc=boot_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        uptime_seconds=round(uptime_secs, 1),
        uptime_human=format_uptime(uptime_secs),
    )


def collect_system_health(
    cpu_interval: float = 0.2,
    disk_path: Optional[str] = None,
) -> SystemHealthReport:
    """Run all system health checks and compute an overall triage status."""
    cpu = get_cpu_info(interval=cpu_interval)
    memory = get_memory_info()
    disks = get_disk_info(disk_path=disk_path)
    uptime = get_uptime_info()

    statuses = [cpu.status, memory.status] + [disk.status for disk in disks]
    warnings: list[str] = []

    if cpu.status in ("WARN", "CRIT"):
        warnings.append(f"High CPU usage: {cpu.usage_percent}% ({cpu.status})")
    if memory.status in ("WARN", "CRIT"):
        warnings.append(f"High RAM usage: {memory.usage_percent}% ({memory.status})")
    for disk in disks:
        if disk.status in ("WARN", "CRIT"):
            warnings.append(
                f"Low disk space on {disk.mountpoint}: {disk.usage_percent}% used ({disk.status})"
            )

    if "CRIT" in statuses:
        overall = "CRIT"
    elif "WARN" in statuses:
        overall = "WARN"
    else:
        overall = "OK"

    return SystemHealthReport(
        hostname=socket.gethostname(),
        os_name=platform.system(),
        os_release=platform.release(),
        os_version=platform.version(),
        architecture=platform.machine(),
        python_version=platform.python_version(),
        cpu=cpu,
        memory=memory,
        disks=disks,
        uptime=uptime,
        overall_status=overall,
        warnings=warnings,
    )
