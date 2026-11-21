"""Builds the compact network feed ProxyShield can read offline.

Inputs (all public):
  * iptoasn.com ip2asn-combined: address range -> ASN, country, description (public domain)
  * APNIC aspop: estimated users per ASN and country (APNIC, re-use with attribution)
Output: out/asn-feed.tsv.gz with lines "start<TAB>end<TAB>class<TAB>cc<TAB>asn", class E for
networks that serve many end users and H for hosting-like networks. Anything else is left out.
"""
import csv
import os
import gzip
import io
import ipaddress
import json
import pathlib
import re
import sys
import time
import urllib.request

ROOT = pathlib.Path(os.environ.get("FEED_WORK") or pathlib.Path(__file__).resolve().parent)
CACHE = ROOT / "cache"
CACHE.mkdir(parents=True, exist_ok=True)
UA = {"User-Agent": "PaperStream-Feed/0 (support@paperstream.dev)"}
MIN_USERS = 50_000
CLOUD = re.compile(
    r"\b(amazon|aws|google|microsoft|azure|ovh|hetzner|digitalocean|linode|akamai|vultr|choopa|contabo|"
    r"leaseweb|m247|scaleway|oracle|alibaba|tencent|cloudflare|ionos|packet|datacamp|zenlayer|"
    r"psychz|quadranet|colocrossing|frantech|buyvm|serverius|stark industries|hostinger|namecheap)\b", re.I)
HOSTING = re.compile(
    r"\b(hosting|hoster|host|cloud|server|servers|vps|datacenter|data center|colo|colocation|dedicated|"
    r"cdn|vpn|proxy|transit)\b", re.I)
ISPISH = re.compile(
    r"\b(isp|internet service|telecom|telekom|broadband|cable|mobile|wireless|communications?|"
    r"telephone|fibre|fiber|dsl)\b", re.I)


def fetch(url, name, max_age=86400):
    path = CACHE / name
    if path.exists() and time.time() - path.stat().st_mtime < max_age:
        return path.read_bytes()
    data = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120).read()
    path.write_bytes(data)
    return data


def eyeball_asns(countries):
    users = {}
    for index, cc in enumerate(sorted(countries)):
        try:
            raw = fetch(f"https://stats.labs.apnic.net/cgi-bin/aspop?c={cc}&f=j", f"aspop-{cc}.json", 7 * 86400)
            for row in json.loads(raw)["Data"]:
                # per country: a hosting network gets "users" in other countries from the VPN traffic leaving it
                if row.get("Users", 0) >= MIN_USERS:
                    users[(int(row["AS"]), cc)] = row["Users"]
        except Exception as error:  # a missing country only costs that country's eyeball flags
            print("aspop", cc, "failed:", str(error)[:80], file=sys.stderr)
        if index % 20 == 0:
            print("aspop", index, "/", len(countries), file=sys.stderr, flush=True)
    return users


def main():
    raw = fetch("https://iptoasn.com/data/ip2asn-combined.tsv.gz", "ip2asn.tsv.gz")
    rows = []
    countries = set()
    with gzip.open(io.BytesIO(raw), "rt", encoding="utf-8", errors="replace") as handle:
        for line in csv.reader(handle, delimiter="\t"):
            start, end, asn, cc, description = line[:5]
            if asn == "0" or cc in ("None", ""):
                continue
            rows.append((start, end, int(asn), cc, description))
            countries.add(cc)
    users = eyeball_asns(countries)

    out = []
    for start, end, asn, cc, description in rows:
        if CLOUD.search(description):
            kind = "H"
        elif HOSTING.search(description) and not ISPISH.search(description):
            kind = "H"
        elif (asn, cc) in users:
            kind = "E"
        else:
            continue
        out.append((int(ipaddress.ip_address(start)), int(ipaddress.ip_address(end)), kind, cc, asn,
                    ipaddress.ip_address(start).version))
    out.sort()
    merged = []
    for item in out:
        if merged and merged[-1][2:5] == item[2:5] and merged[-1][5] == item[5] and item[0] <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], item[1])) + merged[-1][2:]
        else:
            merged.append(item)
    target = ROOT / "out" / "asn-feed.tsv.gz"
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(target, "wt", encoding="utf-8") as handle:
        handle.write("# PaperStream network feed. iptoasn.com (public domain), APNIC aspop (attribution: APNIC).\n")
        handle.write(f"# built {time.strftime('%Y-%m-%d', time.gmtime())}; E end-user network (>= {MIN_USERS} users), H hosting-like\n")
        for start, end, kind, cc, asn, version in merged:
            handle.write(f"{start}\t{end}\t{kind}\t{cc}\t{asn}\t{version}\n")
    print("rows", len(merged), "size", target.stat().st_size)


if __name__ == "__main__":
    main()
