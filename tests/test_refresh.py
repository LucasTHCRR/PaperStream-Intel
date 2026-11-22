import os
import sys
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
