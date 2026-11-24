import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import refresh  # noqa: E402


class OperatorParsingTest(unittest.TestCase):
    def test_mullvad(self):
        data = {"wireguard": {"relays": [{"ipv4_addr_in": "1.2.3.4", "ipv6_addr_in": "2a00::1"}, {"ipv4_addr_in": "5.6.7.8"}]}}
        self.assertEqual(refresh.mullvad(data), {"1.2.3.4", "2a00::1", "5.6.7.8"})

    def test_ivpn(self):
        data = {"wireguard": [{"hosts": [{"host": "1.1.1.1"}, {"hostname": "x"}]}]}
        self.assertEqual(refresh.ivpn(data), {"1.1.1.1"})

    def test_nord_takes_both_stations(self):
        data = [{"station": "1.2.3.4", "ipv6_station": "2a00::2"}, {"station": "5.6.7.8", "ipv6_station": ""}]
        self.assertEqual(refresh.nord(data), {"1.2.3.4", "2a00::2", "5.6.7.8"})

    def test_pia_walks_every_group(self):
        data = {"regions": [{"servers": {"wg": [{"ip": "9.9.9.1"}], "ikev2": [{"ip": "9.9.9.2"}, {}]}}]}
        self.assertEqual(refresh.pia(data), {"9.9.9.1", "9.9.9.2"})


class CloudParsingTest(unittest.TestCase):
    def test_aws_takes_both_families(self):
        data = {"prefixes": [{"ip_prefix": "3.4.12.4/32"}], "ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/40"}]}
        self.assertEqual(refresh.aws(data), {"3.4.12.4/32", "2600:1f00::/40"})

    def test_google_takes_either_prefix(self):
        data = {"prefixes": [{"ipv4Prefix": "34.1.208.0/20"}, {"ipv6Prefix": "2600:1900::/35"}]}
        self.assertEqual(refresh.google_cloud(data), {"34.1.208.0/20", "2600:1900::/35"})

    def test_oracle(self):
        self.assertEqual(refresh.oracle({"regions": [{"cidrs": [{"cidr": "40.233.0.0/19"}]}]}), {"40.233.0.0/19"})

    def test_digitalocean_csv(self):
        text = "5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH\n<html>\n24.144.64.0/22,US,US-NJ,North Bergen,07047\n"
        self.assertEqual(refresh.digitalocean(text), {"5.101.96.0/21", "24.144.64.0/22"})


class CanaryTest(unittest.TestCase):
    def setup_data(self, folder, canary_text="1.2.3.4\n"):
        data = pathlib.Path(folder)
        datasets = data / "datasets"
        datasets.mkdir()
        (datasets / "vpn.txt").write_text("9.9.9.0/24\n")
        (data / "canary.txt").write_text(canary_text)
        previous = refresh.snapshot(datasets, data)
        return data, datasets, previous

    def test_update_that_flags_a_real_player_is_rolled_back(self):
        with tempfile.TemporaryDirectory() as folder:
            data, datasets, previous = self.setup_data(folder)
            (datasets / "vpn.txt").write_text("9.9.9.0/24\n1.2.3.0/24\n")
            refresh.canary(datasets, previous, data)
            self.assertEqual((datasets / "vpn.txt").read_text(), "9.9.9.0/24\n")
            status = json.loads((data / "canary.json").read_text())
            self.assertFalse(status["ok"])
            self.assertTrue(status["rolled_back"])
            self.assertEqual(status["lists"], ["vpn"])

    def test_clean_update_stays(self):
        with tempfile.TemporaryDirectory() as folder:
            data, datasets, previous = self.setup_data(folder)
            (datasets / "vpn.txt").write_text("9.9.9.0/24\n8.8.8.0/24\n")
            refresh.canary(datasets, previous, data)
            self.assertIn("8.8.8.0/24", (datasets / "vpn.txt").read_text())
            status = json.loads((data / "canary.json").read_text())
            self.assertTrue(status["ok"])
            self.assertFalse(status["rolled_back"])

    def test_address_already_flagged_before_does_not_cause_a_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            data = pathlib.Path(folder)
            datasets = data / "datasets"
            datasets.mkdir()
            (datasets / "vpn.txt").write_text("1.2.3.0/24\n")
            (data / "canary.txt").write_text("1.2.3.4\n")
            previous = refresh.snapshot(datasets, data)
            (datasets / "vpn.txt").write_text("1.2.3.0/24\n5.5.5.0/24\n")
            refresh.canary(datasets, previous, data)
            self.assertIn("5.5.5.0/24", (datasets / "vpn.txt").read_text())
            self.assertTrue(json.loads((data / "canary.json").read_text())["ok"])


class BackupTest(unittest.TestCase):
    def test_backup_keeps_seven(self):
        import pathlib
        import sqlite3
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            data = pathlib.Path(folder)
            connection = sqlite3.connect(data / "intel.db")
            connection.execute("CREATE TABLE t (x)")
            connection.execute("INSERT INTO t VALUES (1)")
            connection.commit()
            connection.close()
            (data / "backup").mkdir()
            for day in range(10, 20):
                (data / "backup" / f"intel-202601{day}.db").write_bytes(b"old")
            refresh.backup(data)
            names = sorted(p.name for p in (data / "backup").glob("intel-*.db"))
            self.assertEqual(len(names), 7)
            today = [p for p in (data / "backup").glob("intel-*.db") if p.stat().st_size > 3]
            self.assertEqual(len(today), 1)


if __name__ == "__main__":
    unittest.main()
