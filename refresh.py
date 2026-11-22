# SPDX-License-Identifier: AGPL-3.0-or-later
"""Downloads the public lists and rebuilds the network feed. Run daily, keeps the old file when a source fails."""
import json
import os
import pathlib
import shutil
import subprocess
import sqlite3
import sys
import time
import urllib.request

SOURCES = {
    "vpn": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
            "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt"],
    "datacenter": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
                   "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt"],
    "tor": ["https://check.torproject.org/torbulkexitlist"],
    "proxy": ["https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt"],
}
MINIMUM_LINES = {"vpn": 1000, "datacenter": 1000, "tor": 100, "proxy": 100}
UA = {"User-Agent": "PaperStream-Intel/1.0 (support@paperstream.dev)"}


def replace(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def lists(target):
    for name, urls in SOURCES.items():
        parts = []
        for url in urls:
            try:
                parts.append(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120).read())
            except OSError as error:
                print(f"{name}: {url} failed: {error}")
        text = b"\n".join(parts)
        if text.count(b"\n") < MINIMUM_LINES[name]:
            print(f"{name}: too short, keeping the old file")
            continue
        replace(target / f"{name}.txt", text)
        print(f"{name}: {text.count(chr(10).encode())} lines")


def fetch_json(url, first_line=False):
    raw = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=90).read().decode("utf-8", "replace")
    return json.loads(raw.split("\n", 1)[0] if first_line else raw)


def mullvad(data):
    found = set()
    for relay in data["wireguard"]["relays"]:
        found.update(a for a in (relay.get("ipv4_addr_in"), relay.get("ipv6_addr_in")) if a)
    return found


def ivpn(data):
    return {host["host"] for group in data["wireguard"] for host in group["hosts"] if host.get("host")}


def nord(data):
    return {server[key] for server in data for key in ("station", "ipv6_station") if server.get(key)}


def pia(data):
    return {server["ip"] for region in data["regions"] for servers in region["servers"].values()
            for server in servers if server.get("ip")}


OPERATORS = [
    ("mullvad", "https://api.mullvad.net/public/relays/wireguard/v2", mullvad, False),
    ("ivpn", "https://api.ivpn.net/v5/servers.json", ivpn, False),
    ("nord", "https://api.nordvpn.com/v1/servers?limit=10000", nord, False),
    ("pia", "https://serverlist.piaservers.net/vpninfo/servers/v6", pia, True),
]


def operators(target):
    """Relay addresses the operators publish themselves, so VPN servers outside the public lists are known too.
    An operator that fails keeps its addresses from the last run, so one outage does not shrink the list."""
    known = {}
    previous = target / "operators.json"
    if previous.exists():
        try:
            known = json.loads(previous.read_text())
        except ValueError:
            known = {}
    for name, url, parse, first_line in OPERATORS:
        try:
            addresses = parse(fetch_json(url, first_line))
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"operators: {name} failed: {error}")
            continue
        if len(addresses) < 50:
            print(f"operators: {name} too short ({len(addresses)}), keeping the old list")
            continue
        known[name] = sorted(addresses)
        print(f"operators: {name} {len(addresses)} addresses")
    found = {address for addresses in known.values() for address in addresses}
    if len(found) < 300:
        print("operators: too short, keeping the old file")
        return
    replace(previous, json.dumps(known).encode())
    replace(target / "operators.txt", ("\n".join(sorted(found)) + "\n").encode())
    print("operators:", len(found), "addresses in total")


def feed(target, work):
    environment = dict(os.environ, FEED_WORK=str(work))
    here = pathlib.Path(__file__).resolve().parent
    result = subprocess.run([sys.executable, str(here / "feedbuild.py")], env=environment, capture_output=True, text=True)
    built = work / "out" / "asn-feed.tsv.gz"
    if result.returncode or not built.exists() or built.stat().st_size < 1_000_000:
        print("feed: build failed, keeping the old file", result.stderr[-300:])
        return
    shutil.copy(built, target / "asn-feed.tsv.gz.tmp")
    os.replace(target / "asn-feed.tsv.gz.tmp", target / "asn-feed.tsv.gz")
    print("feed: ok", built.stat().st_size, "bytes")


def backup(data):
    """A consistent copy of the sightings database every night, the last seven are kept."""
    source = data / "intel.db"
    if not source.exists():
        return
    folder = data / "backup"
    folder.mkdir(exist_ok=True)
    target = folder / f"intel-{time.strftime('%Y%m%d')}.db"
    original, copy = sqlite3.connect(source), sqlite3.connect(target)
    try:
        original.backup(copy)
    finally:
        copy.close()
        original.close()
    for old in sorted(folder.glob("intel-*.db"))[:-7]:
        old.unlink()
    print("backup:", target.name)


if __name__ == "__main__":
    data = pathlib.Path(os.environ.get("INTEL_DATA", "data"))
    datasets = data / "datasets"
    datasets.mkdir(parents=True, exist_ok=True)
    lists(datasets)
    operators(datasets)
    feed(datasets, data / "feedwork")
    backup(data)
