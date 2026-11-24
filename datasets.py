# SPDX-License-Identifier: AGPL-3.0-or-later
"""Address data of the intel service: the network feed and the VPN, datacenter, Tor and proxy lists."""
import bisect
import gzip
import ipaddress
import pathlib
import re

LISTS = ("vpn", "datacenter", "tor", "proxy")
KINDS = {"E": "end_user", "H": "hosting", "N": "no_users"}
ENTRY = re.compile(r"^(?:[a-z0-9+.-]+://)?(\[[0-9a-fA-F:]+\]|[0-9a-fA-F]*:[0-9a-fA-F:]+|[0-9.]+)(?::\d+)?(?:/(\d+))?")


class RangeSet:
    """Sorted, merged address ranges per family with a binary search lookup."""

    def __init__(self):
        self.ranges = {4: [], 6: []}
        self.starts = {4: [], 6: []}

    def add(self, version, start, end):
        self.ranges[version].append((start, end))

    def seal(self):
        for version, items in self.ranges.items():
            items.sort()
            merged = []
            for start, end in items:
                if merged and start <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                else:
                    merged.append((start, end))
            self.ranges[version] = merged
            self.starts[version] = [start for start, _ in merged]
        return self

    @classmethod
    def union(cls, *sets):
        merged = cls()
        for one in sets:
            for version in (4, 6):
                merged.ranges[version].extend(one.ranges[version])
        return merged.seal()

    def contains(self, address):
        version = address.version
        value = int(address)
        index = bisect.bisect_right(self.starts[version], value) - 1
        return index >= 0 and value <= self.ranges[version][index][1]

    def __len__(self):
        return len(self.ranges[4]) + len(self.ranges[6])


def parse_entry(line):
    """One list line: address, CIDR block or proxy entry with scheme and port. None when unreadable."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    match = ENTRY.match(line)
    if not match:
        return None
    text = match.group(1).strip("[]")
    try:
        if match.group(2) is not None:
            network = ipaddress.ip_network(f"{text}/{match.group(2)}", strict=False)
            return network.version, int(network.network_address), int(network.broadcast_address)
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return address.version, int(address), int(address)


def read_list(*paths):
    ranges = RangeSet()
    for path in paths:
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                entry = parse_entry(line)
                if entry:
                    ranges.add(*entry)
    return ranges.seal()


def score(reasons):
    """The strongest reason counts fully, every further different reason adds 5, at most 100."""
    values = sorted((SCORES[name] for name in reasons), reverse=True)
    return min(100, values[0] + 5 * (len(values) - 1)) if values else 0


class Feed:
    """Lines "start end class country asn version": E many end users, S small access network, H hosting-like,
    N no measured end users."""

    def __init__(self, path):
        self.rows = {4: ([], []), 6: ([], [])}
        self.count = 0
        self.built = None
        if not path.exists():
            return
        data = []
        with gzip.open(path, "rt", errors="replace") as handle:
            for line in handle:
                if line.startswith("#"):
                    match = re.search(r"built (\d{4}-\d{2}-\d{2})", line)
                    self.built = match.group(1) if match else self.built
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 6:
                    continue
                data.append((int(parts[5]), int(parts[0]), int(parts[1]), parts[2], parts[3], int(parts[4])))
        data.sort()
        for version, start, end, kind, country, asn in data:
            self.rows[version][0].append(start)
            self.rows[version][1].append((end, kind, country, asn))
        self.count = len(data)

    def find(self, address):
        starts, rest = self.rows[address.version]
        value = int(address)
        index = bisect.bisect_right(starts, value) - 1
        if index >= 0 and value <= rest[index][0]:
            _, kind, country, asn = rest[index]
            return kind, country, asn
        return None


# How much a reason weighs for the score (0 to 100). A rough measure, not a probability.
SCORES = {
    "vpn-operator": 100, "tor-exit": 95, "vpn-list": 90, "vpn-community": 85, "open-proxy": 80,
    "reported-by-servers": 70, "registry-hosting": 55, "datacenter-list": 55, "cloud-range": 55, "network-hosting": 50,
}


class Datasets:
    def __init__(self, directory):
        self.directory = pathlib.Path(directory)
        self.feed = Feed(self.directory / "asn-feed.tsv.gz")
        # Hand-picked lists shipped with the code (curated/*.txt), private/*.txt are only copied to the server
        here = pathlib.Path(__file__).parent
        curated = sorted((here / "curated").glob("*.txt")) + sorted((here / "private").glob("*.txt"))
        # One set per source, so every answer can say why it was given
        self.sources = {
            "vpn-list": read_list(self.directory / "vpn.txt"),
            "vpn-operator": read_list(self.directory / "operators.txt"),
            "vpn-community": read_list(self.directory / "community.txt", *curated),
            "datacenter-list": read_list(self.directory / "datacenter.txt"),
            "cloud-range": read_list(self.directory / "clouds.txt"),
            "registry-hosting": read_list(self.directory / "rir-hosting.txt"),
            "tor-exit": read_list(self.directory / "tor.txt"),
            "open-proxy": read_list(self.directory / "proxy.txt"),
        }
        S = self.sources
        self.lists = {
            "vpn": RangeSet.union(S["vpn-list"], S["vpn-operator"], S["vpn-community"]),
            "datacenter": RangeSet.union(S["datacenter-list"], S["cloud-range"], S["registry-hosting"]),
            "tor": S["tor-exit"],
            "proxy": S["open-proxy"],
        }

    def lookup(self, address):
        found = self.feed.find(address)
        kind, country, asn = found if found else (None, None, None)
        reasons = [name for name, ranges in self.sources.items() if ranges.contains(address)]
        if kind == "H":
            reasons.append("network-hosting")
        return {
            "ip": str(address),
            "country": country,
            "asn": asn,
            "network": KINDS.get(kind, "unknown"),
            "vpn": self.lists["vpn"].contains(address),
            "proxy": self.lists["proxy"].contains(address),
            "tor": self.lists["tor"].contains(address),
            "hosting": kind == "H" or self.lists["datacenter"].contains(address),
            "reasons": sorted(reasons, key=lambda name: -SCORES[name]),
            "score": score(reasons),
        }

    def summary(self):
        return {"feed_built": self.feed.built, "feed_ranges": self.feed.count,
                **{f"{name}_ranges": len(ranges) for name, ranges in self.lists.items()}}
