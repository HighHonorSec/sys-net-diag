"""Unit tests for sys_net_diag.network_diag with mocked network calls."""

import socket
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

import psutil

from sys_net_diag.network_diag import (
    _parse_proc_net_route,
    check_dns,
    check_port,
    collect_network_diagnostics,
    detect_default_gateway,
    detect_primary_ip,
    get_local_network_info,
    ping_host,
)


@patch("sys_net_diag.network_diag.socket.getaddrinfo")
def test_check_dns_success(mock_getaddrinfo):
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.190.46", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.190.46", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2607:f8b0:4005:80b::200e", 0, 0, 0)),
    ]
    res = check_dns("google.com")
    assert res.resolved is True
    assert res.status == "OK"
    assert res.ip_addresses == ["142.250.190.46", "2607:f8b0:4005:80b::200e"]
    assert res.latency_ms is not None
    assert res.error is None


@patch("sys_net_diag.network_diag.socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known"))
def test_check_dns_failure(mock_getaddrinfo):
    res = check_dns("nonexistent.invalid")
    assert res.resolved is False
    assert res.status == "FAIL"
    assert res.ip_addresses == []
    assert "Name or service not known" in res.error


def test_check_dns_empty_host():
    res = check_dns("   ")
    assert res.resolved is False
    assert res.status == "FAIL"


@patch("sys_net_diag.network_diag.platform.system", return_value="Windows")
@patch("sys_net_diag.network_diag.subprocess.run")
def test_ping_host_windows_success(mock_run, mock_sys):
    windows_stdout = (
        "\nPinging 8.8.8.8 with 32 bytes of data:\n"
        "Reply from 8.8.8.8: bytes=32 time=11ms TTL=117\n"
        "Reply from 8.8.8.8: bytes=32 time=13ms TTL=117\n\n"
        "Ping statistics for 8.8.8.8:\n"
        "    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
        "Approximate round trip times in milli-seconds:\n"
        "    Minimum = 11ms, Maximum = 13ms, Average = 12ms\n"
    )
    mock_run.return_value = SimpleNamespace(returncode=0, stdout=windows_stdout, stderr="")

    res = ping_host("8.8.8.8", count=2, timeout=2.0)
    assert res.reachable is True
    assert res.packets_sent == 2
    assert res.packets_received == 2
    assert res.packet_loss_percent == 0.0
    assert res.min_ms == 11.0
    assert res.avg_ms == 12.0
    assert res.max_ms == 13.0
    assert res.status == "OK"
    mock_run.assert_called_once()
    assert mock_run.call_args[0][0][:4] == ["ping", "-n", "2", "-w"]


@patch("sys_net_diag.network_diag.platform.system", return_value="Linux")
@patch("sys_net_diag.network_diag.subprocess.run")
def test_ping_host_linux_partial_loss_warn(mock_run, mock_sys):
    linux_stdout = (
        "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n"
        "--- 1.1.1.1 ping statistics ---\n"
        "4 packets transmitted, 3 received, 25% packet loss, time 3004ms\n"
        "rtt min/avg/max/mdev = 10.2/14.5/20.1/4.1 ms\n"
    )
    mock_run.return_value = SimpleNamespace(returncode=0, stdout=linux_stdout, stderr="")

    res = ping_host("1.1.1.1", count=4, timeout=2.0)
    assert res.reachable is True
    assert res.packets_received == 3
    assert res.packet_loss_percent == 25.0
    assert res.avg_ms == 14.5
    assert res.status == "WARN"


@patch("sys_net_diag.network_diag.platform.system", return_value="Darwin")
@patch("sys_net_diag.network_diag.subprocess.run")
def test_ping_host_macos_unreachable(mock_run, mock_sys):
    mac_stdout = (
        "PING 192.0.2.1 (192.0.2.1): 56 data bytes\n"
        "--- 192.0.2.1 ping statistics ---\n"
        "2 packets transmitted, 0 packets received, 100.0% packet loss\n"
    )
    mock_run.return_value = SimpleNamespace(returncode=2, stdout=mac_stdout, stderr="")

    res = ping_host("192.0.2.1", count=2, timeout=1.5)
    assert res.reachable is False
    assert res.packet_loss_percent == 100.0
    assert res.status == "FAIL"


@patch("sys_net_diag.network_diag.platform.system", return_value="Linux")
@patch("sys_net_diag.network_diag.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=5))
def test_ping_host_timeout_expired(mock_run, mock_sys):
    res = ping_host("8.8.8.8", count=2, timeout=1.0)
    assert res.reachable is False
    assert res.status == "FAIL"
    assert "timed out" in res.error.lower()


@patch("sys_net_diag.network_diag.socket.socket")
def test_detect_primary_ip_via_udp_socket(mock_socket_cls):
    sock_inst = MagicMock()
    sock_inst.getsockname.return_value = ("192.168.1.42", 54321)
    mock_socket_cls.return_value = sock_inst

    ip = detect_primary_ip()
    assert ip == "192.168.1.42"
    sock_inst.connect.assert_called_once_with(("8.8.8.8", 80))
    sock_inst.close.assert_called_once()


@patch("sys_net_diag.network_diag.socket.gethostbyname", return_value="10.0.0.15")
@patch("sys_net_diag.network_diag.socket.gethostname", return_value="workstation")
@patch("sys_net_diag.network_diag.socket.socket", side_effect=OSError("network down"))
def test_detect_primary_ip_fallback(mock_sock, mock_hostname, mock_gethostbyname):
    assert detect_primary_ip() == "10.0.0.15"


def test_parse_proc_net_route():
    # 0101A8C0 in little-endian corresponds to 192.168.1.1 on x86/ARM
    sample = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
    )
    gw = _parse_proc_net_route(sample)
    assert gw in ("192.168.1.1", "1.1.168.192")  # Endianness-aware check


@patch("sys_net_diag.network_diag.platform.system", return_value="Windows")
@patch("sys_net_diag.network_diag.subprocess.run")
def test_detect_default_gateway_windows(mock_run, mock_sys):
    route_out = (
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.42     25\n"
    )
    mock_run.return_value = SimpleNamespace(returncode=0, stdout=route_out, stderr="")
    gw, method = detect_default_gateway()
    assert gw == "192.168.1.1"
    assert method == "route print"


@patch("sys_net_diag.network_diag.platform.system", return_value="Linux")
@patch("sys_net_diag.network_diag.os.path.exists", return_value=False)
@patch("sys_net_diag.network_diag.subprocess.run")
def test_detect_default_gateway_linux_ip_route_fallback(mock_run, mock_exists, mock_sys):
    mock_run.return_value = SimpleNamespace(
        returncode=0,
        stdout="default via 10.10.0.1 dev eth0 proto dhcp metric 100\n",
        stderr="",
    )
    gw, method = detect_default_gateway()
    assert gw == "10.10.0.1"
    assert method == "ip route"


@patch("sys_net_diag.network_diag.platform.system", return_value="Darwin")
@patch("sys_net_diag.network_diag.subprocess.run")
def test_detect_default_gateway_macos(mock_run, mock_sys):
    mock_run.return_value = SimpleNamespace(
        returncode=0,
        stdout="   route to: default\n  gateway: 172.16.0.1\n  interface: en0\n",
        stderr="",
    )
    gw, method = detect_default_gateway()
    assert gw == "172.16.0.1"
    assert method == "route get default"


@patch("sys_net_diag.network_diag.detect_default_gateway", return_value=("192.168.1.1", "route print"))
@patch("sys_net_diag.network_diag.detect_primary_ip", return_value="192.168.1.50")
@patch("sys_net_diag.network_diag.psutil.net_if_stats")
@patch("sys_net_diag.network_diag.psutil.net_if_addrs")
def test_get_local_network_info(mock_addrs, mock_stats, mock_ip, mock_gw):
    mock_addrs.return_value = {
        "Ethernet": [
            SimpleNamespace(family=socket.AF_INET, address="192.168.1.50"),
            SimpleNamespace(family=psutil.AF_LINK, address="AA:BB:CC:DD:EE:FF"),
        ]
    }
    mock_stats.return_value = {"Ethernet": SimpleNamespace(isup=True)}

    info = get_local_network_info()
    assert info.primary_ip == "192.168.1.50"
    assert info.default_gateway == "192.168.1.1"
    assert info.status == "OK"
    assert len(info.interfaces) == 1
    assert info.interfaces[0].mac == "AA:BB:CC:DD:EE:FF"


@patch("sys_net_diag.network_diag.socket.create_connection")
def test_check_port_open(mock_conn):
    ctx = MagicMock()
    mock_conn.return_value.__enter__.return_value = ctx

    res = check_port("google.com", 443, timeout=2.0)
    assert res.is_open is True
    assert res.status == "OPEN"
    assert res.service == "HTTPS"
    assert res.latency_ms is not None
    mock_conn.assert_called_once_with(("google.com", 443), timeout=2.0)


@patch("sys_net_diag.network_diag.socket.create_connection", side_effect=ConnectionRefusedError("Connection refused"))
def test_check_port_closed(mock_conn):
    res = check_port("127.0.0.1", 8080, timeout=1.0)
    assert res.is_open is False
    assert res.status == "CLOSED"
    assert res.service == "HTTP-Alt"
    assert "Connection refused" in res.error


@patch("sys_net_diag.network_diag.socket.create_connection", side_effect=TimeoutError("timed out"))
def test_check_port_timeout(mock_conn):
    res = check_port("192.0.2.1", 22, timeout=1.5)
    assert res.is_open is False
    assert res.status == "CLOSED"
    assert "timed out" in res.error.lower()


@patch("sys_net_diag.network_diag.check_port")
@patch("sys_net_diag.network_diag.ping_host")
@patch("sys_net_diag.network_diag.check_dns")
@patch("sys_net_diag.network_diag.get_local_network_info")
def test_collect_network_diagnostics_status(mock_local, mock_dns, mock_ping, mock_port):
    from sys_net_diag.network_diag import DnsCheckResult, LocalNetworkInfo, PingResult, PortCheckResult

    mock_local.return_value = LocalNetworkInfo("192.168.1.10", "192.168.1.1", [], "route", "OK")
    mock_dns.return_value = DnsCheckResult("google.com", True, ["142.250.1.1"], 8.5, "OK")
    mock_ping.return_value = PingResult("8.8.8.8", True, 4, 4, 0.0, 10.0, 11.0, 12.0, "OK")
    mock_port.return_value = PortCheckResult("google.com", 443, "HTTPS", False, 100.0, "CLOSED", "refused")

    report = collect_network_diagnostics(
        dns_hosts=["google.com"],
        ping_hosts=["8.8.8.8"],
        port_host="google.com",
        ports=[443],
    )
    assert report.overall_status == "WARN"
    assert len(report.issues) == 1
    assert "443" in report.issues[0]
