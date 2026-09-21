import contextlib
import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path

import log_analysis


AUTH_LOG = """\
Jan 10 10:00:01 host sshd[100]: Invalid user admin from 203.0.113.10 port 51000
Jan 10 10:00:02 host sshd[101]: Invalid user admin from 203.0.113.10 port 51001
Jan 10 10:00:03 host sshd[102]: Invalid user oracle from 198.51.100.7 port 51002
Jan 10 10:00:04 host sshd[103]: Accepted password for tmoore from 192.0.2.5 port 51003
"""

ROTATED_AUTH_LOG = """\
Jan 09 09:00:01 host sshd[90]: Invalid user backup from 2001:db8::25 port 50000
"""

UFW_LOG = """\
Jan 10 10:00:05 host kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=192.0.2.10 PROTO=TCP DPT=22
Jan 10 10:00:06 host kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.99 DST=192.0.2.10 PROTO=TCP DPT=443
Jan 10 10:00:07 host kernel: [UFW ALLOW] IN=eth0 SRC=198.51.100.7 DST=192.0.2.10 PROTO=TCP DPT=22
"""


class LogAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logs_dir = Path(self.temp_dir.name)
        (self.logs_dir / "auth.log").write_text(AUTH_LOG, encoding="utf-8")
        with gzip.open(
            self.logs_dir / "auth.log.1.gz", mode="wt", encoding="utf-8"
        ) as rotated_log:
            rotated_log.write(ROTATED_AUTH_LOG)
        (self.logs_dir / "ufw.log").write_text(UFW_LOG, encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_invalid_user_counts_include_rotated_gzip_logs(self):
        self.assertEqual(
            log_analysis.get_invalid_logins(self.logs_dir),
            {"admin": 2, "oracle": 1, "backup": 1},
        )

    def test_source_ip_correlation(self):
        self.assertEqual(
            log_analysis.compare_invalid_ips(self.logs_dir), ["203.0.113.10"]
        )
        self.assertEqual(
            log_analysis.compare_invalid_IPs(self.logs_dir), ["203.0.113.10"]
        )

    def test_user_auth_times(self):
        self.assertEqual(
            log_analysis.get_user_auth_times("tmoore", self.logs_dir),
            ["Jan 10 10:00:04"],
        )

    def test_analysis_summary(self):
        result = log_analysis.analyze_logs(self.logs_dir, top=2)
        self.assertEqual(result.files_processed, 3)
        self.assertEqual(result.auth_files_processed, 2)
        self.assertEqual(result.ufw_files_processed, 1)
        self.assertEqual(result.invalid_login_attempts, 4)
        self.assertEqual(result.unique_invalid_usernames, 3)
        self.assertEqual(result.unique_invalid_login_ips, 3)
        self.assertEqual(result.unique_scanning_ips, 2)
        self.assertEqual(result.unique_overlap_ips, 1)
        self.assertEqual(result.top_invalid_usernames[0], ("admin", 2))

    def test_json_cli_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = log_analysis.main(
                ["--logs-dir", str(self.logs_dir), "--json", "--user", "tmoore"]
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["invalid_login_attempts"], 4)
        self.assertEqual(payload["overlap_ips"], ["203.0.113.10"])
        self.assertEqual(payload["user_query"]["timestamps"], ["Jan 10 10:00:04"])

    def test_missing_directory_has_clear_error(self):
        with self.assertRaisesRegex(FileNotFoundError, "does not exist"):
            log_analysis.analyze_logs(self.logs_dir / "missing")


if __name__ == "__main__":
    unittest.main()
