# SPDX-License-Identifier: AGPL-3.0-or-later
"""Downloads the public lists and rebuilds the network feed. Run daily, keeps the old file when a source fails."""
import ipaddress
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sqlite3
import sys
import time
import urllib.request

from datasets import ENTRY, Datasets, parse_entry

SOURCES = {
    "vpn": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
            "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt"],
    "datacenter": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
                   "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt"],
    "tor": ["https://check.torproject.org/torbulkexitlist"],
    # monosans (MIT), vakhov (MIT), proxifly (GPL-3.0): open proxies that are listed as working today
    "proxy": ["https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
              "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist.txt",
              "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt"],
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


def rolling(target, name, days, now=None):
    """Open proxies and Tor exits come and go. An address stays on the list for some days after the last time it was
    seen, so a list that is a day old does not already let it through. The history lives next to the list."""
    path = target / f"{name}.txt"
    history = target / f"{name}-history.json"
    if not path.exists():
        return
    now = int(now if now is not None else time.time())
    try:
        seen = json.loads(history.read_text()) if history.exists() else {}
    except ValueError:
        seen = {}
    for line in path.read_text().splitlines():
        match = ENTRY.match(line.strip()) if line.strip() and not line.startswith("#") else None
        if match:
            seen[match.group(1).strip("[]")] = now
    seen = {host: stamp for host, stamp in seen.items() if now - stamp < days * 86400}
    replace(history, json.dumps(seen).encode())
    replace(path, ("\n".join(sorted(seen)) + "\n").encode())
    print(f"{name}: {len(seen)} addresses (kept {days} days)")


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


def surfshark(data):
    """Surfshark publishes host names only, so they are resolved here (a part of the load balanced answers is enough)."""
    found = set()
    for server in data:
        try:
            for info in socket.getaddrinfo(server["connectionName"], None, proto=socket.IPPROTO_TCP):
                found.add(info[4][0])
        except (OSError, KeyError):
            continue
    return found


OPERATORS = [
    ("mullvad", "https://api.mullvad.net/public/relays/wireguard/v2", mullvad, False),
    ("ivpn", "https://api.ivpn.net/v5/servers.json", ivpn, False),
    ("nord", "https://api.nordvpn.com/v1/servers?limit=10000", nord, False),
    ("pia", "https://serverlist.piaservers.net/vpninfo/servers/v6", pia, True),
    ("surfshark", "https://api.surfshark.com/v4/server/clusters/all", surfshark, False),
]


def aws(data):
    return {item["ip_prefix"] for item in data["prefixes"]} | {item["ipv6_prefix"] for item in data["ipv6_prefixes"]}


def google_cloud(data):
    return {item.get("ipv4Prefix") or item.get("ipv6Prefix") for item in data["prefixes"]} - {None}


def oracle(data):
    return {item["cidr"] for region in data["regions"] for item in region["cidrs"]}


def digitalocean(text):
    return {line.split(",", 1)[0] for line in text.splitlines() if line[:1].isdigit() or line[:1] in "0123456789abcdef"}


# name, url, parser, is text (not JSON). The providers publish these ranges themselves.
CLOUDS = [
    ("aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", aws, False),
    ("google", "https://www.gstatic.com/ipranges/cloud.json", google_cloud, False),
    ("oracle", "https://docs.oracle.com/iaas/tools/public_ip_ranges.json", oracle, False),
    ("digitalocean", "https://digitalocean.com/geo/google.csv", digitalocean, True),
]


def clouds(target):
    """Ranges of the big cloud providers, so hosting space inside other networks is known too.
    A provider that fails keeps its ranges from the last run."""
    known = {}
    previous = target / "clouds.json"
    if previous.exists():
        try:
            known = json.loads(previous.read_text())
        except ValueError:
            known = {}
    for name, url, parse, is_text in CLOUDS:
        try:
            if is_text:
                ranges = parse(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=90).read().decode("utf-8", "replace"))
            else:
                ranges = parse(fetch_json(url))
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"clouds: {name} failed: {error}")
            continue
        if len(ranges) < 100:
            print(f"clouds: {name} too short ({len(ranges)}), keeping the old list")
            continue
        known[name] = sorted(ranges)
        print(f"clouds: {name} {len(ranges)} ranges")
    found = {entry for ranges in known.values() for entry in ranges}
    if len(found) < 1000:
        print("clouds: too short, keeping the old file")
        return
    replace(previous, json.dumps(known).encode())
    replace(target / "clouds.txt", ("\n".join(sorted(found)) + "\n").encode())
    print("clouds:", len(found), "ranges in total")


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


RIR_FILES = [
    ("ripe.db.inetnum.gz", "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"),
    ("ripe.db.inet6num.gz", "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz"),
    ("apnic.db.inetnum.gz", "https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz"),
    ("apnic.db.inet6num.gz", "https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz"),
    ("afrinic.db.gz", "https://ftp.afrinic.net/dbase/afrinic.db.gz"),
    ("lacnic.db.gz", "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz"),
]
RIR_EVERY_DAYS = 3


def rir(target, work):
    """Hosting ranges from the public databases of the regional registries (RIPE, APNIC, AFRINIC, LACNIC), found by
    network name and description. Rebuilt every few days with bin/rirbuild. Only this derived list is kept."""
    here = pathlib.Path(__file__).resolve().parent
    binary = here / "bin" / "rirbuild"
    output = target / "rir-hosting.txt"
    if not binary.exists():
        return
    if output.exists() and time.time() - output.stat().st_mtime < RIR_EVERY_DAYS * 86400:
        return
    folder = work / "rir"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    try:
        for name, url in RIR_FILES:
            part = folder / (name + ".part")
            result = subprocess.run(["curl", "-sSfL", "--max-time", "900", "-A", UA["User-Agent"], "-o", str(part), url],
                                    capture_output=True, text=True)
            if result.returncode:
                print(f"rir: {name} failed: {result.stderr[-120:]}")
                return
            part.rename(folder / name)
        temporary = target / "rir-hosting.txt.tmp"
        result = subprocess.run([str(binary), str(folder), str(temporary)], capture_output=True, text=True)
        lines = temporary.read_text().count("\n") if temporary.exists() else 0
        if result.returncode or lines < 5000:
            print("rir: build failed or too short, keeping the old file", result.stderr[-200:])
            temporary.unlink(missing_ok=True)
            return
        os.replace(temporary, output)
        print("rir:", lines, "ranges")
    finally:
        shutil.rmtree(folder, ignore_errors=True)


JOE = "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/{}.txt"
# Public lists of VPN servers: name, url. Joe12387 is CC0, tn3w Apache-2.0, az0 GPL-3.0.
COMMUNITY = [(f"joe12387-{service}", JOE.format(service)) for service in
             ("airvpn", "ivpn", "mullvad", "nordvpn", "ovpn", "pia", "protonvpn", "riseupvpn", "surfshark", "windscribe")] + [
    ("tn3w-protonvpn", "https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/master/protonvpn_ips.txt"),
    ("az0-vpn-ip", "http://az0-vpnip-public.oooninja.com/ip.txt"),
]


def community(target):
    """VPN server lists that other projects publish. A source that fails keeps its addresses from the last run."""
    known = {}
    previous = target / "community.json"
    if previous.exists():
        try:
            known = json.loads(previous.read_text())
        except ValueError:
            known = {}
    for name, url in COMMUNITY:
        try:
            text = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=90).read().decode("utf-8", "replace")
        except OSError as error:
            print(f"community: {name} failed: {error}")
            continue
        lines = {line.strip() for line in text.splitlines() if parse_entry(line)}
        if len(lines) < 10:
            print(f"community: {name} too short ({len(lines)}), keeping the old list")
            continue
        known[name] = sorted(lines)
        print(f"community: {name} {len(lines)} entries")
    found = {entry for lines in known.values() for entry in lines}
    if len(found) < 1000:
        print("community: too short, keeping the old file")
        return
    replace(previous, json.dumps(known).encode())
    replace(target / "community.txt", ("\n".join(sorted(found)) + "\n").encode())
    print("community:", len(found), "entries in total")


def feed(target, work):
    """Builds the network feed. The Rust program (bin/feedbuild) is used when it is there, the Python script
    is the fallback if it is missing or fails."""
    environment = dict(os.environ, FEED_WORK=str(work))
    here = pathlib.Path(__file__).resolve().parent
    commands = []
    if (here / "bin" / "feedbuild").exists():
        commands.append([str(here / "bin" / "feedbuild")])
    commands.append([sys.executable, str(here / "feedbuild.py")])
    built = work / "out" / "asn-feed.tsv.gz"
    for command in commands:
        built.unlink(missing_ok=True)
        result = subprocess.run(command, env=environment, capture_output=True, text=True)
        if not result.returncode and built.exists() and built.stat().st_size >= 1_000_000:
            shutil.copy(built, target / "asn-feed.tsv.gz.tmp")
            os.replace(target / "asn-feed.tsv.gz.tmp", target / "asn-feed.tsv.gz")
            print("feed: ok", pathlib.Path(command[-1]).name, built.stat().st_size, "bytes")
            return
        print("feed: build failed with", pathlib.Path(command[-1]).name, result.stderr[-300:])
    print("feed: all builds failed, keeping the old file")


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


CANARY_FILE = "canary.txt"


def snapshot(datasets, data):
    """A copy of the current data, to come back to if the new data flags a real player."""
    previous = data / "datasets.prev"
    shutil.rmtree(previous, ignore_errors=True)
    shutil.copytree(datasets, previous)
    return previous


def flagged_canaries(path, addresses):
    sets = Datasets(path)
    found = set()
    for text in addresses:
        try:
            result = sets.lookup(ipaddress.ip_address(text))
        except ValueError:
            continue
        if result["vpn"] or result["proxy"] or result["tor"] or result["hosting"]:
            found.add(text)
    return found, sets


def canary(datasets, previous, data):
    """Addresses of real players (home and mobile connections) must not be flagged by new data. If the update flags
    one that the old data did not, the old data come back and the status says so. The canary list stays on the
    server and out of the repository: it holds addresses of real people."""
    path = data / CANARY_FILE
    status = data / "canary.json"
    if not path.exists() or previous is None:
        return
    addresses = [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]
    new_flagged, sets = flagged_canaries(datasets, addresses)
    old_flagged, _ = flagged_canaries(previous, addresses)
    fresh = sorted(new_flagged - old_flagged)
    rolled_back = False
    offenders = []
    if fresh:
        for name, ranges in sets.lists.items():
            if any(ranges.contains(ipaddress.ip_address(a)) for a in fresh):
                offenders.append(name)
        print(f"canary: the update flags {len(fresh)} real address(es), lists: {offenders}. Restoring the old data.")
        shutil.rmtree(datasets)
        shutil.copytree(previous, datasets)
        rolled_back = True
    else:
        print(f"canary: ok, {len(addresses)} addresses checked")
    replace(status, json.dumps({"checked_at": int(time.time()), "checked": len(addresses), "flagged": len(fresh),
                                "ok": not fresh, "rolled_back": rolled_back, "lists": offenders}).encode())


if __name__ == "__main__":
    data = pathlib.Path(os.environ.get("INTEL_DATA", "data"))
    datasets = data / "datasets"
    datasets.mkdir(parents=True, exist_ok=True)
    previous = snapshot(datasets, data) if any(datasets.iterdir()) else None
    lists(datasets)
    rolling(datasets, "proxy", 10)
    rolling(datasets, "tor", 3)
    operators(datasets)
    clouds(datasets)
    community(datasets)
    # "quick" skips the heavy part (feed and backup), it runs every four hours
    if "quick" not in sys.argv[1:]:
        rir(datasets, data / "feedwork")
        feed(datasets, data / "feedwork")
    canary(datasets, previous, data)
    if "quick" not in sys.argv[1:]:
        backup(data)
