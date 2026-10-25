"""Unit tests for Sentinel-ARP network traffic test generator utilities."""

from unittest.mock import MagicMock, patch
import pytest

from tools.generate_test_arp_traffic import (
    build_arp_reply_packet,
    is_allowed_private_address as arp_is_private,
    main as arp_main,
    parse_args as arp_parse_args,
    send_test_arp_replies,
)
from tools.generate_test_bandwidth_traffic import (
    is_allowed_private_address as bw_is_private,
    main as bw_main,
    parse_args as bw_parse_args,
    run_bandwidth_test,
)


class TestIPValidation:
    """Test RFC 1918 private IPv4 validation."""

    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "10.254.1.99",
            "172.16.0.1",
            "172.24.10.20",
            "172.31.255.254",
            "192.168.1.1",
            "192.168.100.50",
            " 192.168.1.10 ",
        ],
    )
    def test_valid_private_ips(self, ip):
        assert arp_is_private(ip) is True
        assert bw_is_private(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "172.15.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "256.0.0.1",
            "invalid_ip",
            "",
            None,
        ],
    )
    def test_invalid_or_public_ips(self, ip):
        assert arp_is_private(ip) is False
        assert bw_is_private(ip) is False


class TestARPTrafficGenerator:
    """Test ARP test generator argument parsing and packet sending."""

    def test_missing_required_args_raises_system_exit(self):
        with pytest.raises(SystemExit):
            arp_parse_args([])

        with pytest.raises(SystemExit):
            arp_parse_args(["--target", "192.168.1.50"])

    def test_valid_arguments_parsed(self):
        args = arp_parse_args(
            ["--target", "192.168.1.50", "--gateway", "192.168.1.1", "--iface", "eth0", "--count", "5"]
        )
        assert args.target == "192.168.1.50"
        assert args.gateway == "192.168.1.1"
        assert args.iface == "eth0"
        assert args.count == 5

    def test_public_target_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            arp_main(["--target", "8.8.8.8", "--gateway", "192.168.1.1", "--iface", "eth0"])
        assert exc_info.value.code == 1

    def test_public_gateway_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            arp_main(["--target", "192.168.1.50", "--gateway", "1.1.1.1", "--iface", "eth0"])
        assert exc_info.value.code == 1

    def test_invalid_count_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            arp_main(["--target", "192.168.1.50", "--gateway", "192.168.1.1", "--iface", "eth0", "--count", "0"])
        assert exc_info.value.code == 1

        with pytest.raises(SystemExit) as exc_info2:
            arp_main(["--target", "192.168.1.50", "--gateway", "192.168.1.1", "--iface", "eth0", "--count", "100"])
        assert exc_info2.value.code == 1

    def test_packet_construction(self):
        pkt = build_arp_reply_packet("192.168.1.1", "192.168.1.50", "00:11:22:33:44:55")
        assert pkt["ARP"].op == 2  # 'is-at'
        assert pkt["ARP"].psrc == "192.168.1.1"
        assert pkt["ARP"].pdst == "192.168.1.50"
        assert pkt["ARP"].hwsrc == "00:11:22:33:44:55"

    @patch("tools.generate_test_arp_traffic.sendp")
    @patch("tools.generate_test_arp_traffic.time.sleep")
    def test_send_test_arp_replies_mocked(self, mock_sleep, mock_sendp):
        result = send_test_arp_replies(
            target_ip="192.168.1.50",
            gateway_ip="192.168.1.1",
            iface="eth0",
            count=3,
            delay_seconds=0.01,
            custom_mac="aa:bb:cc:dd:ee:ff",
        )
        assert result == 0
        assert mock_sendp.call_count == 3
        assert mock_sleep.call_count == 2


class TestBandwidthTrafficGenerator:
    """Test Bandwidth test generator argument parsing and UDP streaming."""

    def test_missing_required_args_raises_system_exit(self):
        with pytest.raises(SystemExit):
            bw_parse_args([])

        with pytest.raises(SystemExit):
            bw_parse_args(["--target", "192.168.1.50"])

    def test_valid_arguments_parsed(self):
        args = bw_parse_args(["--target", "10.0.0.5", "--port", "9000", "--seconds", "10", "--mbps", "2.5"])
        assert args.target == "10.0.0.5"
        assert args.port == 9000
        assert args.seconds == 10
        assert args.mbps == 2.5

    def test_public_target_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            bw_main(["--target", "93.184.216.34", "--port", "8080"])
        assert exc_info.value.code == 1

    def test_invalid_port_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            bw_main(["--target", "192.168.1.50", "--port", "0"])
        assert exc_info.value.code == 1

        with pytest.raises(SystemExit) as exc_info2:
            bw_main(["--target", "192.168.1.50", "--port", "70000"])
        assert exc_info2.value.code == 1

    def test_invalid_seconds_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            bw_main(["--target", "192.168.1.50", "--port", "8080", "--seconds", "-5"])
        assert exc_info.value.code == 1

        with pytest.raises(SystemExit) as exc_info2:
            bw_main(["--target", "192.168.1.50", "--port", "8080", "--seconds", "500"])
        assert exc_info2.value.code == 1

    def test_invalid_mbps_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            bw_main(["--target", "192.168.1.50", "--port", "8080", "--mbps", "0"])
        assert exc_info.value.code == 1

        with pytest.raises(SystemExit) as exc_info2:
            bw_main(["--target", "192.168.1.50", "--port", "8080", "--mbps", "150"])
        assert exc_info2.value.code == 1

    def test_run_bandwidth_test_bounded_execution(self):
        mock_sock = MagicMock()
        packets, total_bytes, elapsed = run_bandwidth_test(
            target_ip="192.168.1.50",
            port=9999,
            seconds=0.1,  # Short duration
            mbps=1.0,
            sock=mock_sock,
        )
        assert packets > 0
        assert total_bytes == packets * 1024
        assert elapsed >= 0.1
        assert mock_sock.sendto.called
