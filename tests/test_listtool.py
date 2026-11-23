import ipaddress
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import list_manager as tool  # noqa: E402


class FakeData:
    def __init__(self, vpn=(), hosting=()):
        self.vpn = {ipaddress.ip_address(a) for a in vpn}
        self.hosting = {ipaddress.ip_address(a) for a in hosting}

    def lookup(self, address):
        return {"vpn": address in self.vpn, "proxy": False, "tor": False, "hosting": address in self.hosting}


class ParseTest(unittest.TestCase):
    def test_mixed_formats(self):
        text = "8.8.8.8, 1.1.1.1:8080\nhttp://9.9.9.9/x 2001:4860:4860::8888 8.8.4.0/24 8.8.8.8"
        found, dropped = tool.parse(text)
        self.assertEqual(set(found), {"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.0/24", "2001:4860:4860::8888"})

    def test_private_and_too_broad_are_dropped(self):
        found, dropped = tool.parse("10.0.0.1 192.168.1.5 8.8.8.8 1.0.0.0/4 999.1.1.1")
        self.assertEqual(found, ["8.8.8.8"])
        self.assertGreaterEqual(dropped, 3)

    def test_cidr_is_normalised(self):
        self.assertEqual(tool.parse("8.8.4.7/24")[0], ["8.8.4.0/24"])


class SplitTest(unittest.TestCase):
    def test_known_and_new(self):
        data = FakeData(vpn=["8.8.8.8"], hosting=["9.9.9.9"])
        new, known = tool.split_new(data, ["8.8.8.8", "9.9.9.9", "1.1.1.1"])
        self.assertEqual((new, known), (["1.1.1.1"], 2))

    def test_only_vpn_ignores_hosting(self):
        data = FakeData(vpn=["8.8.8.8"], hosting=["9.9.9.9"])
        new, known = tool.split_new(data, ["8.8.8.8", "9.9.9.9"], only_vpn=True)
        self.assertEqual((new, known), (["9.9.9.9"], 1))

    def test_range_needs_both_ends(self):
        data = FakeData(vpn=["8.8.4.0", "8.8.4.255"])
        self.assertEqual(tool.split_new(data, ["8.8.4.0/24"])[1], 1)
        self.assertEqual(tool.split_new(FakeData(vpn=["8.8.4.0"]), ["8.8.4.0/24"])[0], ["8.8.4.0/24"])


class AddTest(unittest.TestCase):
    def test_merge_without_duplicates(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = pathlib.Path(folder)
            path, count = tool.add_entries("Hola VPN!", ["8.8.8.8", "1.1.1.1"], directory)
            self.assertEqual((path.name, count), ("hola-vpn.txt", 2))
            path, count = tool.add_entries("hola-vpn", ["1.1.1.1", "9.9.9.9"], directory)
            self.assertEqual(count, 1)
            self.assertEqual(path.read_text().split(), ["1.1.1.1", "8.8.8.8", "9.9.9.9"])


if __name__ == "__main__":
    unittest.main()
