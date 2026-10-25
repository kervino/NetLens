
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ANALYZER = PROJECT_ROOT / "src" / "analyze.py"


FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures"

SAMPLE_PCAP = (
    FIXTURE_DIR / "netlens-wireshark-practice.pcap"
)

SCAN_PCAP = (
    FIXTURE_DIR / "netlens-concept24-portscan.pcap"
)

OFFICE_PCAP = (
    FIXTURE_DIR / "netlens-office-synthetic.pcap"
)


REPORT_DIR = PROJECT_ROOT / "reports"



class TestNetLens(unittest.TestCase):

    def test_valid_pcap(self):
        result = subprocess.run(
            [sys.executable, str(ANALYZER), str(SAMPLE_PCAP)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Total packets: 5", result.stdout)
        self.assertIn("TCP packets: 3", result.stdout)
        self.assertIn("UDP packets: 2", result.stdout)

    def test_invalid_pcap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid_file = Path(temp_dir) / "invalid.pcap"
            invalid_file.write_bytes(b"Not a real PCAP")

            result = subprocess.run(
                [sys.executable, str(ANALYZER), str(invalid_file)],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Unable to read capture",
                result.stderr
            )
            self.assertNotIn("Traceback", result.stderr)

    
    def test_detect_port_scan(self):
        result = subprocess.run(
            [sys.executable, str(ANALYZER), str(SCAN_PCAP)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "Potential TCP SYN port scan detected!",
            result.stdout
        )

        report_path = (
            REPORT_DIR
            / "netlens-concept24-portscan_summary.json"
        )

        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )

        findings = report["scan_findings"]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "192.0.2.10")
        self.assertEqual(
            findings[0]["destination"],
            "198.51.100.50"
        )
        self.assertEqual(findings[0]["unique_ports"], 7)
        self.assertEqual(
            findings[0]["ports"],
            [21, 22, 23, 25, 80, 443, 8080]
        )


    def test_no_scan_office_capture(self):
        result = subprocess.run(
            [sys.executable, str(ANALYZER), str(OFFICE_PCAP)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "No potential TCP SYN port scans detected.",
            result.stdout
        )

        report_path = (
            REPORT_DIR
            / "netlens-office-synthetic_summary.json"
        )

        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )

        self.assertEqual(report["scan_findings"], [])


if __name__ == "__main__":
    unittest.main()
