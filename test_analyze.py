import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from main import analyze_pcap, build_report_text


class TestNetworkTrafficAnalyzer(unittest.TestCase):
    def test_analyze_pcap_and_build_report(self):
        # Minimal PCAP-like payload for validation.
        # Payload mínimo em formato PCAP para validação.
        packet = (
            b'\x00\x00' * 6 +
            b'\x08\x00' +
            b'\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02'
            + b'\x00\x50\x00\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x02\x00\x04\x00')
            tmp.write((0).to_bytes(4, 'little') + (0).to_bytes(4, 'little') + len(packet).to_bytes(4, 'little') + len(packet).to_bytes(4, 'little'))
            tmp.write(packet)

        try:
            data = analyze_pcap(tmp_path)
            report = build_report_text(data)
            self.assertIn('Packets analyzed:', report)
            self.assertIn('Top source:', report)
            self.assertIn('Top destination:', report)
            self.assertIn('Suspicious ports:', report)
            self.assertIn('Potential C2:', report)
            self.assertIn('IPs involved:', report)
            self.assertIn('Ports:', report)
            self.assertIn('Protocols:', report)
            self.assertIn('DNS queries:', report)
            self.assertIn('HTTP requests:', report)
            self.assertIn('Connections suspeitas:', report)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


if __name__ == '__main__':
    unittest.main()
