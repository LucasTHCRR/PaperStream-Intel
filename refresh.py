"""Downloads the public lists and rebuilds the network feed. Run daily, keeps the old file when a source fails."""
import os
import pathlib
import shutil
import subprocess
import sys
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


if __name__ == "__main__":
    data = pathlib.Path(os.environ.get("INTEL_DATA", "data"))
    datasets = data / "datasets"
    datasets.mkdir(parents=True, exist_ok=True)
    lists(datasets)
    feed(datasets, data / "feedwork")
