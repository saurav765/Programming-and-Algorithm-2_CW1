# testcode.py — Full unit tests for upgraded main.py

import unittest
from unittest.mock import MagicMock, patch
import tempfile
import os
import socket

from main import (
    validate_ipv4,
    detect_service,
    get_risk_weight,
    calculate_risk_level,
    scan_port,
    identify_from_banner,
    grab_banner,
    is_host_reachable,
    build_export_data,
    export_json,
    PortScannerEngine,
    RISK_LOW_MAX,
    RISK_MEDIUM_MAX,
)


class TestMain(unittest.TestCase):

    # --------------------------------------------------
    # IPv4 Validation
    # --------------------------------------------------
    def test_validate_ipv4(self):
        self.assertTrue(validate_ipv4("192.168.1.1"))
        self.assertFalse(validate_ipv4("256.0.0.1"))
        print("✅ validate_ipv4 tested OK")

    # --------------------------------------------------
    # Service Detection
    # --------------------------------------------------
    def test_detect_service_known(self):
        self.assertEqual(detect_service(22), "SSH")
        print("✅ detect_service (known port) tested OK")

    def test_detect_service_unknown(self):
        result = detect_service(65000)
        self.assertIsInstance(result, str)
        print("✅ detect_service (fallback logic) tested OK")

    # --------------------------------------------------
    # Risk Weight & Risk Level
    # --------------------------------------------------
    def test_get_risk_weight(self):
        self.assertEqual(get_risk_weight("Telnet"), 5)
        self.assertEqual(get_risk_weight("HTTP"), 1)
        print("✅ get_risk_weight tested OK")

    def test_calculate_risk_level(self):
        self.assertEqual(calculate_risk_level(RISK_LOW_MAX)[0], "Low")
        self.assertEqual(calculate_risk_level(RISK_MEDIUM_MAX)[0], "Medium")
        self.assertEqual(calculate_risk_level(RISK_MEDIUM_MAX + 1)[0], "High")
        print("✅ calculate_risk_level tested OK")

    # --------------------------------------------------
    # Port Scanning (safe local test)
    # --------------------------------------------------
    def test_scan_port_closed(self):
        self.assertFalse(scan_port("127.0.0.1", 0))
        print("✅ scan_port tested OK")

    # --------------------------------------------------
    # Banner Identification
    # --------------------------------------------------
    def test_identify_from_banner(self):
        banner = "SSH-2.0-OpenSSH_8.2"
        self.assertEqual(identify_from_banner(banner), "SSH")
        print("✅ identify_from_banner tested OK")

    # --------------------------------------------------
    # Banner Grabbing (mocked socket)
    # --------------------------------------------------
    @patch("main.socket.socket")
    def test_grab_banner(self, mock_socket):
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Test\r\n"
        mock_socket.return_value.__enter__.return_value = mock_conn

        banner = grab_banner("127.0.0.1", 80, service_hint="HTTP")
        self.assertIn("HTTP/1.1", banner)
        print("✅ grab_banner tested OK")

    # --------------------------------------------------
    # Reachability (mocked)
    # --------------------------------------------------
    @patch("main.socket.socket")
    def test_is_host_reachable(self, mock_socket):
        mock_conn = MagicMock()
        mock_conn.connect_ex.return_value = 0
        mock_socket.return_value.__enter__.return_value = mock_conn

        self.assertTrue(is_host_reachable("127.0.0.1"))
        print("✅ is_host_reachable tested OK")

    # --------------------------------------------------
    # Export Data Builder
    # --------------------------------------------------
    def test_build_export_data(self):
        results = [
            {"port": 22, "status": "Open", "service": "SSH", "banner": ""},
            {"port": 80, "status": "Closed", "service": "-", "banner": ""},
        ]
        data = build_export_data("127.0.0.1", 22, 80, results, duration_s=1.5)

        self.assertIn("duration_seconds", data)
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["open_count"], 1)
        print("✅ build_export_data tested OK")

    # --------------------------------------------------
    # JSON Export
    # --------------------------------------------------
    def test_export_json(self):
        data = {"test": 123}
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            path = tmp.name

        export_json(data, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("123", content)
        os.remove(path)
        print("✅ export_json tested OK")

    # --------------------------------------------------
    # PortScannerEngine (mock scan + banner)
    # --------------------------------------------------
    @patch("main.scan_port", return_value=True)
    @patch("main.grab_banner", return_value="SSH-2.0-Test")
    def test_engine(self, mock_banner, mock_scan):
        results_cb = MagicMock()
        progress_cb = MagicMock()
        complete_cb = MagicMock()

        engine = PortScannerEngine(
            host="127.0.0.1",
            start_port=22,
            end_port=22,
            on_result=results_cb,
            on_progress=progress_cb,
            on_complete=complete_cb,
        )

        engine.run()

        self.assertTrue(results_cb.called)
        self.assertTrue(progress_cb.called)
        self.assertTrue(complete_cb.called)
        print("✅ PortScannerEngine tested OK")


if __name__ == "__main__":
    unittest.main()