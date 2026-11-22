import gzip
import ipaddress
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as intel  # noqa: E402
from datasets import Datasets, parse_entry  # noqa: E402

FEED = ("# PaperStream network feed.\n# built 2026-11-21; E end-user network, H hosting-like\n"
        "{a}\t{b}\tE\tDE\t3320\t4\n{c}\t{d}\tH\tFR\t16276\t4\n"
        "{e}\t{f}\tN\tDE\t58087\t4\n{g}\t{h}\tS\tNL\t9009\t4\n").format(
    a=int(ipaddress.ip_address("80.187.0.0")), b=int(ipaddress.ip_address("80.187.255.255")),
    c=int(ipaddress.ip_address("51.75.0.0")), d=int(ipaddress.ip_address("51.75.255.255")),
    e=int(ipaddress.ip_address("45.133.74.0")), f=int(ipaddress.ip_address("45.133.74.255")),
    g=int(ipaddress.ip_address("84.22.0.0")), h=int(ipaddress.ip_address("84.22.255.255")))
IVPN = "45.133.193.0/24\n"


def write(path, text):
    with open(path, "w") as handle:
        handle.write(text)


class IntelTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        data = self.directory.name
        sets = os.path.join(data, "datasets")
        os.makedirs(sets)
        with gzip.open(os.path.join(sets, "asn-feed.tsv.gz"), "wt") as handle:
            handle.write(FEED)
        write(os.path.join(sets, "vpn.txt"), "# list\n" + IVPN + "2a00:1450:1::/48\n")
        write(os.path.join(sets, "tor.txt"), "185.220.101.1\n")
        write(os.path.join(sets, "operators.txt"), "5.6.7.8\n2a07:d883:703:3::f001\n")
        write(os.path.join(sets, "proxy.txt"), "socks5://8.8.4.4:1080\n[2606:4700::1]:8080\n")
        write(os.path.join(sets, "datacenter.txt"), "34.120.0.0/24\n")
        self.app = intel.create_app(data)
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.db.close()
        self.directory.cleanup()

    def ip(self, text):
        response = self.client.get("/v1/ip/" + text)
        return response.status_code, response.get_json()

    def test_end_user_network(self):
        code, body = self.ip("80.187.100.44")
        self.assertEqual(code, 200)
        self.assertEqual((body["network"], body["country"], body["asn"]), ("end_user", "DE", 3320))
        self.assertFalse(any(body[k] for k in ("vpn", "proxy", "tor", "hosting")))

    def test_hosting_network_and_lists(self):
        self.assertTrue(self.ip("51.75.1.1")[1]["hosting"])
        self.assertTrue(self.ip("34.120.0.5")[1]["hosting"])
        self.assertTrue(self.ip("45.133.193.73")[1]["vpn"])
        self.assertTrue(self.ip("185.220.101.1")[1]["tor"])
        self.assertTrue(self.ip("8.8.4.4")[1]["proxy"])
        self.assertTrue(self.ip("2606:4700::1")[1]["proxy"])
        self.assertTrue(self.ip("2a00:1450:1::5")[1]["vpn"])
        self.assertFalse(self.ip("45.133.194.1")[1]["vpn"])
        self.assertTrue(self.ip("5.6.7.8")[1]["vpn"])
        self.assertTrue(self.ip("2a07:d883:703:3::f001")[1]["vpn"])

    def test_networks_without_users_are_reported_but_not_called_hosting(self):
        code, body = self.ip("45.133.74.77")
        self.assertEqual((body["network"], body["country"], body["asn"], body["hosting"]), ("no_users", "DE", 58087, False))
        body = self.ip("84.22.1.1")[1]
        self.assertEqual((body["network"], body["country"], body["asn"], body["hosting"]), ("unknown", "NL", 9009, False))

    def test_unknown_private_and_invalid(self):
        self.assertEqual(self.ip("9.9.9.9")[1]["network"], "unknown")
        self.assertEqual(self.ip("192.168.1.5")[1]["network"], "private")
        self.assertEqual(self.ip("nonsense")[0], 422)

    def test_me_answers_for_the_caller(self):
        response = self.client.get("/v1/me", environ_overrides={"REMOTE_ADDR": "51.75.1.1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual((response.get_json()["ip"], response.get_json()["hosting"]), ("51.75.1.1", True))
        proxied = self.client.get("/v1/me", headers={"X-Real-IP": "80.187.100.44"},
                                  environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(proxied.get_json()["network"], "end_user")
        direct = self.client.get("/v1/me", headers={"X-Real-IP": "80.187.100.44"},
                                 environ_overrides={"REMOTE_ADDR": "9.9.9.9"})
        self.assertEqual(direct.get_json()["ip"], "9.9.9.9", "the header only counts from the local proxy")

    def test_rate_limit(self):
        original = intel.LOOKUPS_PER_MINUTE
        intel.LOOKUPS_PER_MINUTE = 3
        try:
            codes = [self.ip("9.9.9.9")[0] for _ in range(5)]
        finally:
            intel.LOOKUPS_PER_MINUTE = original
        self.assertEqual(codes, [200, 200, 200, 429, 429])

    def report(self, install, ips):
        return self.client.post("/v1/report", json={"install": install, "ips": ips})

    def test_sightings_count_distinct_servers(self):
        for number in range(2):
            self.assertEqual(self.report(f"{number:032x}", ["45.133.193.73", "45.133.193.73"]).get_json()["accepted"], 2)
        body = self.ip("45.133.193.73")[1]
        self.assertEqual((body["seen_by"], body["community"]), (2, False))
        self.report("f" * 32, ["45.133.193.73"])
        body = self.ip("45.133.193.73")[1]
        self.assertEqual((body["seen_by"], body["community"]), (3, True))

    def test_report_rejects_bad_input(self):
        self.assertEqual(self.client.post("/v1/report", json={"install": "short", "ips": []}).status_code, 400)
        self.assertEqual(self.client.post("/v1/report", json={"install": "a" * 32, "ips": "x"}).status_code, 400)
        self.assertEqual(self.client.post("/v1/report", json={"install": "a" * 32, "ips": ["1.1.1.1"] * 201}).status_code, 400)
        self.assertEqual(self.report("a" * 32, ["10.0.0.1", "garbage", "127.0.0.1", "1.1.1.1"]).get_json()["accepted"], 1)

    def test_forget_removes_everything_of_one_install(self):
        self.report("a" * 32, ["1.1.1.1", "1.0.0.1"])
        self.report("b" * 32, ["1.1.1.1"])
        self.assertEqual(self.client.post("/v1/forget", json={"install": "a" * 32}).get_json()["deleted"], 2)
        self.assertEqual(self.ip("1.1.1.1")[1]["seen_by"], 1)
        self.assertEqual(self.ip("1.0.0.1")[1]["seen_by"], 0)

    def test_old_sightings_do_not_count(self):
        self.report("a" * 32, ["1.1.1.1"])
        database = sqlite3.connect(os.path.join(self.directory.name, "intel.db"))
        database.execute("UPDATE sightings SET day = day - 15")
        database.commit()
        database.close()
        self.assertEqual(self.ip("1.1.1.1")[1]["seen_by"], 0)

    def test_daily_limit_per_install(self):
        original = intel.REPORTS_PER_DAY
        intel.REPORTS_PER_DAY = 3
        try:
            self.assertEqual(self.report("a" * 32, ["1.1.1.1", "1.0.0.1", "8.8.8.8"]).status_code, 200)
            self.assertEqual(self.report("a" * 32, ["9.9.9.9"]).status_code, 429)
        finally:
            intel.REPORTS_PER_DAY = original

    def test_nothing_about_the_sender_is_stored(self):
        self.report("a" * 32, ["1.1.1.1"])
        database = sqlite3.connect(os.path.join(self.directory.name, "intel.db"))
        rows = database.execute("SELECT * FROM sightings").fetchall()
        database.close()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("a" * 32, rows[0])
        self.assertEqual(len(rows[0][1]), 64)

    def test_feed_download_and_conditional_request(self):
        first = self.client.get("/feed/asn-feed.tsv.gz")
        self.assertEqual(first.status_code, 200)
        self.assertTrue(gzip.decompress(first.data).startswith(b"# PaperStream"))
        again = self.client.get("/feed/asn-feed.tsv.gz", headers={"If-None-Match": first.headers["ETag"]})
        self.assertEqual(again.status_code, 304)

    def test_operator_relays_download(self):
        response = self.client.get("/feed/operators.txt")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"5.6.7.8", response.data)

    def test_healthz_reports_stale_data(self):
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        old = os.path.join(self.directory.name, "datasets", "vpn.txt")
        os.utime(old, (1, 1))
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["stale"], ["vpn.txt"])

    def test_stats_count_answers_without_addresses(self):
        self.ip("9.9.9.9")
        self.ip("45.133.193.73")
        body = self.client.get("/v1/stats").get_json()
        self.assertEqual((body["answered"]["requests"], body["answered"]["flagged"]), (2, 1))
        self.assertIn("vpn_ranges", body)
        database = sqlite3.connect(os.path.join(self.directory.name, "intel.db"))
        self.assertEqual(database.execute("SELECT COUNT(*) FROM daily WHERE kind NOT IN ('requests','flagged')").fetchone()[0], 0)
        database.close()

    def test_stats_can_be_filtered_by_days(self):
        self.ip("9.9.9.9")
        database = sqlite3.connect(os.path.join(self.directory.name, "intel.db"))
        day = int(__import__("time").time() // 86400)
        database.executemany("INSERT INTO daily VALUES (?, ?, ?)", [
            (day - 3, "requests", 10), (day - 3, "flagged", 4), (day - 40, "requests", 100), (day - 40, "flagged", 50)])
        database.commit()
        database.close()
        week = self.client.get("/v1/stats?days=7").get_json()["answered"]
        self.assertEqual((week["requests"], week["flagged"], week["days"]), (11, 4, 7))
        every = self.client.get("/v1/stats").get_json()["answered"]
        self.assertEqual((every["requests"], every["flagged"]), (111, 54))
        rows = self.client.get("/v1/stats/daily?days=5").get_json()
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[-4]["requests"], 10)
        self.assertEqual(rows[-1]["requests"], 1)

    def test_healthz_reports_load(self):
        self.ip("9.9.9.9")
        load = self.client.get("/healthz").get_json()["load"]
        self.assertIn("requests_last_minute", load)
        self.assertIn("requests_last_5_minutes", load)
        self.assertGreaterEqual(load.get("service_memory_mb", 1), 0)

    def test_list_entries(self):
        self.assertEqual(parse_entry("socks5://1.2.3.4:1080"), (4, 16909060, 16909060))
        self.assertEqual(parse_entry("1.2.3.0/24")[2] - parse_entry("1.2.3.0/24")[1], 255)
        self.assertIsNone(parse_entry("# comment"))
        self.assertIsNone(parse_entry("not an address"))
        self.assertEqual(parse_entry("[2001:db8::1]:8080")[0], 6)

    def test_missing_files_do_not_break_start(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(Datasets(empty).lookup(ipaddress.ip_address("9.9.9.9"))["network"], "unknown")


if __name__ == "__main__":
    unittest.main()
