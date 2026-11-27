"""Unit tests for sys_net_diag.system_health."""

from types import SimpleNamespace
from unittest.mock import patch

from sys_net_diag.system_health import (
    collect_system_health,
    format_uptime,
    get_cpu_info,
    get_disk_info,
    get_memory_info,
    get_uptime_info,
)


def test_format_uptime():
    assert format_uptime(45) == "45s"
    assert format_uptime(125) == "2m 5s"
    assert format_uptime(3661) == "1h 1m 1s"
    assert format_uptime(90061) == "1d 1h 1m 1s"


@patch("sys_net_diag.system_health.psutil.getloadavg", return_value=(0.512, 0.734, 0.889))
@patch("sys_net_diag.system_health.psutil.cpu_count", side_effect=[4, 8])
@patch("sys_net_diag.system_health.psutil.cpu_percent", return_value=23.4)
def test_get_cpu_info_with_load(mock_pct, mock_count, mock_load):
    cpu = get_cpu_info(interval=0.1)
    assert cpu.usage_percent == 23.4
    assert cpu.physical_cores == 4
    assert cpu.logical_cores == 8
    assert cpu.load_avg == (0.51, 0.73, 0.89)
    assert cpu.status == "OK"
    mock_pct.assert_called_once_with(interval=0.1)


@patch("sys_net_diag.system_health.psutil.getloadavg", side_effect=AttributeError("unsupported"))
@patch("sys_net_diag.system_health.psutil.cpu_count", side_effect=[2, 4])
@patch("sys_net_diag.system_health.psutil.cpu_percent", return_value=96.2)
def test_get_cpu_info_crit_no_loadavg(mock_pct, mock_count, mock_load):
    cpu = get_cpu_info()
    assert cpu.load_avg is None
    assert cpu.status == "CRIT"


@patch("sys_net_diag.system_health.psutil.getloadavg", side_effect=RuntimeError("PdhAddEnglishCounterW failed"))
@patch("sys_net_diag.system_health.psutil.cpu_count", side_effect=[4, 8])
@patch("sys_net_diag.system_health.psutil.cpu_percent", return_value=12.0)
def test_get_cpu_info_loadavg_runtime_error(mock_pct, mock_count, mock_load):
    cpu = get_cpu_info()
    assert cpu.load_avg is None
    assert cpu.status == "OK"


@patch("sys_net_diag.system_health.psutil.swap_memory")
@patch("sys_net_diag.system_health.psutil.virtual_memory")
def test_get_memory_info(mock_vm, mock_swap):
    mock_vm.return_value = SimpleNamespace(
        total=16 * 1024**3,
        available=4 * 1024**3,
        used=12 * 1024**3,
        percent=82.5,
    )
    mock_swap.return_value = SimpleNamespace(
        total=4 * 1024**3,
        used=1 * 1024**3,
        percent=25.0,
    )
    mem = get_memory_info()
    assert mem.usage_percent == 82.5
    assert mem.status == "WARN"
    assert mem.swap_percent == 25.0


@patch("sys_net_diag.system_health.psutil.disk_usage")
@patch("sys_net_diag.system_health.psutil.disk_partitions")
def test_get_disk_info_filters_and_handles_permission_error(mock_parts, mock_usage):
    mock_parts.return_value = [
        SimpleNamespace(device="C:\\", mountpoint="C:\\", fstype="NTFS", opts="rw,fixed"),
        SimpleNamespace(device="D:\\", mountpoint="D:\\", fstype="CDFS", opts="ro,cdrom"),
        SimpleNamespace(device="/dev/loop0", mountpoint="/snap/core", fstype="squashfs", opts="ro"),
        SimpleNamespace(device="/dev/sdb1", mountpoint="/mnt/restricted", fstype="ext4", opts="rw"),
    ]
    mock_usage.side_effect = [
        SimpleNamespace(total=500_000, used=250_000, free=250_000, percent=50.0),
        PermissionError("Access denied"),
    ]
    disks = get_disk_info()
    assert len(disks) == 1
    assert disks[0].mountpoint == "C:\\"
    assert disks[0].status == "OK"


@patch("sys_net_diag.system_health.psutil.disk_usage")
def test_get_disk_info_custom_path(mock_usage):
    mock_usage.return_value = SimpleNamespace(total=1000, used=960, free=40, percent=96.0)
    disks = get_disk_info(disk_path="/var/log")
    assert len(disks) == 1
    assert disks[0].mountpoint == "/var/log"
    assert disks[0].status == "CRIT"


@patch("sys_net_diag.system_health.time.time", return_value=1_700_090_061.0)
@patch("sys_net_diag.system_health.psutil.boot_time", return_value=1_700_000_000.0)
def test_get_uptime_info(mock_boot, mock_time):
    uptime = get_uptime_info()
    assert uptime.uptime_seconds == 90061.0
    assert uptime.uptime_human == "1d 1h 1m 1s"
    assert uptime.boot_time_utc.endswith("Z")


@patch("sys_net_diag.system_health.get_uptime_info")
@patch("sys_net_diag.system_health.get_disk_info")
@patch("sys_net_diag.system_health.get_memory_info")
@patch("sys_net_diag.system_health.get_cpu_info")
def test_collect_system_health_aggregates_warnings(mock_cpu, mock_mem, mock_disks, mock_up):
    from sys_net_diag.system_health import CpuInfo, DiskPartitionInfo, MemoryInfo, UptimeInfo

    mock_cpu.return_value = CpuInfo(85.0, 4, 8, (1.0, 1.0, 1.0), "WARN")
    mock_mem.return_value = MemoryInfo(1000, 400, 600, 60.0, 0, 0, 0.0, "OK")
    mock_disks.return_value = [
        DiskPartitionInfo("/dev/sda1", "/", "ext4", 1000, 960, 40, 96.0, "CRIT")
    ]
    mock_up.return_value = UptimeInfo("2026-01-01T00:00:00Z", 3600.0, "1h 0m 0s")

    report = collect_system_health()
    assert report.overall_status == "CRIT"
    assert len(report.warnings) == 2
    assert any("CPU" in w for w in report.warnings)
    assert any("disk" in w.lower() for w in report.warnings)
