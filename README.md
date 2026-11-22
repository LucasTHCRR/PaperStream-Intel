# PaperStream intel service

Free address lookups for anti-VPN plugins, the network feed ProxyShield reads offline, and an
opt-in sightings counter. Flask and SQLite, no accounts, no access logs.

```
GET  /v1/ip/{ip}        verdict: network, country, asn, vpn, proxy, tor, hosting, seen_by, community
GET  /feed/asn-feed.tsv.gz
POST /v1/report         {"install": "<32-64 hex>", "ips": [...up to 200]}   (ProxyShield, opt-in)
POST /v1/forget         {"install": "<id>"}   deletes everything that install sent
GET  /v1/stats
```

Data: iptoasn.com (public domain) and APNIC aspop for the feed, X4BNet/lists_vpn (MIT), the Tor
bulk exit list and monosans/proxy-list (MIT) for the lists, plus the relay lists Mullvad and IVPN publish themselves. `refresh.py` rebuilds all of it
nightly. Reports are kept 14 days under a hash of the install id.

Run locally: `INTEL_DATA=./data python3 refresh.py`, then
`INTEL_DATA=./data python3 -c "from app import create_app; create_app().run(port=5191)"`.
Tests: `python3 -m unittest discover -s tests`. Deploy: `deploy/deploy.sh` (root server, DNS, TLS, nginx, systemd).
