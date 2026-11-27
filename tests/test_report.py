"""Unit tests for sys_net_diag.report."""

import json
import pytest

from sys_net_diag.network_diag import (
    DnsCheckResult,
    InterfaceInfo,
    LocalNetworkInfo,
    NetworkDiagnosticsReport,
    PingResult,
    PortCheckResult,
)
from sys_net_diag.report import (
    build_report,
    export_report,
    format_bytes,
    format_report_json,
    format_report_text,
)
from sys_net_diag.system_health import (
    CpuInfo,
    DiskPartitionInfo,
    MemoryInfo,
    SystemHealthReport,
    UptimeInfo,
)


def _sample_report():
    sys_report = SystemHealthReport(
        hostname="support-laptop",
        os_name="Windows",
        os_release="11",
        os_version="10.0.22631",
        architecture="AMD64",
        python_version="3.12.10",
        cpu=CpuInfo(24.5, 4, 8, None, "OK"),
        memory=MemoryInfo(16 * 1024**3, 8 * 1024**3, 8 * 1024**3, 50.0, 0, 0, 0.0, "OK"),
        disks=[DiskPartitionInfo("C:\\", "C:\\", "NTFS", 500 * 1024**3, 250 * 1024**3, 250 * 1024**3, 50.0, "OK")],
        uptime=UptimeInfo("2026-11-26T10:00:00Z", 7200.0, "2h 0m 0s"),
        overall_status="OK",
        warnings=[],
    )
    net_report = NetworkDiagnosticsReport(
        local_network=LocalNetworkInfo(
            primary_ip="192.168.1.25",
            default_gateway="192.168.1.1",
            interfaces=[InterfaceInfo("Wi-Fi", True, ["192.168.1.25"], [], "AA:BB:CC:DD:EE:FF")],
            gateway_detection_method="route print",
            status="OK",
        ),
        dns_checks=[DnsCheckResult("google.com", True, ["142.250.190.46"], 12.4, "OK")],
        ping_checks=[PingResult("8.8.8.8", True, 4, 4, 0.0, 9.0, 11.0, 14.0, "OK")],
        port_checks=[PortCheckResult("google.com", 443, "HTTPS", True, 20.1, "OPEN")],
        overall_status="OK",
        issues=[],
    )
    return build_report(system_health=sys_report, network_diagnostics=net_report)


def test_format_bytes():
    assert format_bytes(512) == "512 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024**3) == "1.0 GB"


def test_format_report_text_contains_sections():
    report = _sample_report()
    text = format_report_text(report)
    assert "[SYSTEM HEALTH]" in text
    assert "[NETWORK DIAGNOSTICS]" in text
    assert "[L1 TRIAGE SUMMARY]" in text
    assert "support-laptop" in text
    assert "192.168.1.1" in text
    assert "google.com" in text
    assert "OPEN" in text


def test_format_report_json_valid():
    report = _sample_report()
    raw = format_report_json(report)
    parsed = json.loads(raw)
    assert parsed["tool"] == "sys-net-diag"
    assert parsed["overall_status"] == "OK"
    assert parsed["system_health"]["hostname"] == "support-laptop"
    assert parsed["network_diagnostics"]["local_network"]["default_gateway"] == "192.168.1.1"


def test_export_report_txt_and_json(tmp_path):
    report = _sample_report()

    txt_path, txt_fmt = export_report(report, tmp_path / "nested" / "diag.txt")
    assert txt_fmt == "txt"
    assert txt_path.exists()
    assert "[SYSTEM HEALTH]" in txt_path.read_text(encoding="utf-8")

    json_path, json_fmt = export_report(report, tmp_path / "diag.json")
    assert json_fmt == "json"
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["overall_status"] == "OK"


def test_export_report_unknown_extension_raises(tmp_path):
    report = _sample_report()
    with pytest.raises(ValueError, match="Cannot infer export format"):
        export_report(report, tmp_path / "diag.csv")


def test_export_report_explicit_format_override(tmp_path):
    report = _sample_report()
    path, fmt = export_report(report, tmp_path / "diag.out", fmt="json")
    assert fmt == "json"
    assert json.loads(path.read_text(encoding="utf-8"))["tool"] == "sys-net-diag"
