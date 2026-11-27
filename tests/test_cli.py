"""Unit tests for sys_net_diag.cli."""

import json
from unittest.mock import patch

import pytest

from sys_net_diag.cli import main, parse_hosts, parse_ports
from sys_net_diag.network_diag import (
    DnsCheckResult,
    LocalNetworkInfo,
    NetworkDiagnosticsReport,
    PingResult,
    PortCheckResult,
)
from sys_net_diag.system_health import (
    CpuInfo,
    DiskPartitionInfo,
    MemoryInfo,
    SystemHealthReport,
    UptimeInfo,
)


def _mock_sys_report(status="OK"):
    return SystemHealthReport(
        hostname="test-host",
        os_name="Linux",
        os_release="6.8",
        os_version="#1",
        architecture="x86_64",
        python_version="3.12.10",
        cpu=CpuInfo(10.0, 2, 4, (0.1, 0.2, 0.3), status),
        memory=MemoryInfo(8 * 1024**3, 6 * 1024**3, 2 * 1024**3, 25.0, 0, 0, 0.0, "OK"),
        disks=[DiskPartitionInfo("/dev/sda1", "/", "ext4", 100_000, 30_000, 70_000, 30.0, "OK")],
        uptime=UptimeInfo("2026-11-26T00:00:00Z", 3600.0, "1h 0m 0s"),
        overall_status=status,
        warnings=[] if status == "OK" else ["High CPU"],
    )


def _mock_net_report(status="OK"):
    return NetworkDiagnosticsReport(
        local_network=LocalNetworkInfo("10.0.0.5", "10.0.0.1", [], "/proc/net/route", "OK"),
        dns_checks=[DnsCheckResult("google.com", True, ["142.250.1.1"], 5.0, "OK")],
        ping_checks=[PingResult("8.8.8.8", True, 4, 4, 0.0, 5.0, 6.0, 7.0, "OK")],
        port_checks=[PortCheckResult("google.com", 443, "HTTPS", True, 12.0, "OPEN")],
        overall_status=status,
        issues=[] if status == "OK" else ["Degraded network"],
    )


def test_parse_ports_variants():
    assert parse_ports(["80", "443"]) == [80, 443]
    assert parse_ports(["22,80,443", "443,3389"]) == [22, 80, 443, 3389]


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        parse_ports(["abc"])
    with pytest.raises(ValueError):
        parse_ports(["70000"])


def test_parse_hosts():
    assert parse_hosts(["google.com,cloudflare.com", "github.com"]) == [
        "google.com",
        "cloudflare.com",
        "github.com",
    ]


@patch("sys_net_diag.cli.collect_network_diagnostics")
@patch("sys_net_diag.cli.collect_system_health")
def test_cli_json_output_and_export(mock_sys, mock_net, tmp_path, capsys):
    mock_sys.return_value = _mock_sys_report()
    mock_net.return_value = _mock_net_report()

    export_file = tmp_path / "out.json"
    code = main(
        [
            "--dns-host",
            "example.com",
            "--ping-host",
            "1.1.1.1",
            "--ports",
            "80,443",
            "--format",
            "json",
            "--export",
            str(export_file),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    stdout_data = json.loads(captured.out)
    assert stdout_data["overall_status"] == "OK"
    assert "Report exported (json)" in captured.err
    assert export_file.exists()

    mock_net.assert_called_once_with(
        dns_hosts=["example.com"],
        ping_hosts=["1.1.1.1"],
        ping_count=4,
        port_host="google.com",
        ports=[80, 443],
        timeout=3.0,
    )


@patch("sys_net_diag.cli.collect_network_diagnostics")
@patch("sys_net_diag.cli.collect_system_health")
def test_cli_skip_flags_and_quiet_txt_export(mock_sys, mock_net, tmp_path, capsys):
    mock_sys.return_value = _mock_sys_report()
    export_file = tmp_path / "sys_only.txt"

    code = main(["--skip-network", "--quiet", "-o", str(export_file)])
    assert code == 0
    mock_sys.assert_called_once()
    mock_net.assert_not_called()
    assert capsys.readouterr().out == ""
    content = export_file.read_text(encoding="utf-8")
    assert "[SYSTEM HEALTH]" in content
    assert "[NETWORK DIAGNOSTICS]" not in content


@patch("sys_net_diag.cli.collect_network_diagnostics")
@patch("sys_net_diag.cli.collect_system_health")
def test_cli_strict_exit_code(mock_sys, mock_net):
    mock_sys.return_value = _mock_sys_report(status="WARN")
    mock_net.return_value = _mock_net_report(status="OK")

    assert main(["--quiet"]) == 0
    assert main(["--quiet", "--strict"]) == 1


def test_cli_cannot_skip_both():
    with pytest.raises(SystemExit) as exc_info:
        main(["--skip-system", "--skip-network"])
    assert exc_info.value.code == 2
