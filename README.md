# PaperStream Intel

Free anti-VPN lookups for Minecraft plugins, bots and websites, and the network feed that
[ProxyShield](https://modrinth.com/plugin/proxyshield) reads offline. Flask and SQLite, no accounts,
no access logs. Live at [intel.paperstream.dev](https://intel.paperstream.dev), documented at
[paperstream.dev/api](https://paperstream.dev/api), and you can test your own connection at
[paperstream.dev/vpn](https://paperstream.dev/vpn).

## API

```
GET  /v1/ip/{ip}              verdict: network, country, asn, vpn, proxy, tor, hosting, seen_by, community
GET  /v1/me                   the same for the address that asks
GET  /v1/stats?days=7         answered lookups of the last 7 days (no days = all time) and dataset sizes
GET  /v1/stats/daily?days=30  answered lookups per day
GET  /feed/asn-feed.tsv.gz    network feed for offline use
GET  /feed/operators.txt      relay addresses the VPN operators publish, one per line
GET  /healthz                 200 while every dataset is fresh, 503 with the stale files otherwise; also lookups per minute and memory
POST /v1/report               {"install": "<32-64 hex>", "ips": [...up to 200]}   (ProxyShield, opt-in)
POST /v1/forget               {"install": "<id>"}   deletes everything that install sent
```

600 lookups a minute per address, answered with 429 and `Retry-After` beyond that. The rate limit
keeps a salted hash of the address in memory only.

## Data

- `asn-feed.tsv.gz`: iptoasn.com (public domain) and APNIC aspop. Classes `E` end-user network,
  `H` hosting-like, `N` nobody measured, `S` small access network.
- VPN and datacenter lists: X4BNet/lists_vpn (MIT). Tor: the Tor bulk exit list. Open proxies:
  monosans/proxy-list (MIT).
- Relay lists that Mullvad, IVPN, NordVPN and Private Internet Access publish themselves.
- `curated/hola.txt`: 673 HolaVPN addresses, shared by [ImZowi](https://github.com/ImZowi). Thank you!
- `curated/proton.txt`: 926 Proton VPN server addresses from the server list of the official Proton VPN app.
- Cloud ranges that AWS, Google Cloud, Oracle and DigitalOcean publish count as datacenter space, and the Surfshark servers are resolved from its public server list.
- Lists of VPN servers that other projects publish, refreshed every four hours: [Joe12387/open-source-vpn-ip-lists](https://github.com/Joe12387/open-source-vpn-ip-lists) (CC0), [tn3w/ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) (Apache-2.0) and [az0/vpn_ip](https://github.com/az0/vpn_ip) (GPL-3.0). Thank you!
- Hosting ranges found in the public databases of the regional registries (RIPE, APNIC, AFRINIC, LACNIC) by network name and description, rebuilt every three days. Only this derived list of ranges is kept, the databases themselves are not stored or passed on.
- VPN address lists from [NazgulCoder/IPLists](https://github.com/NazgulCoder/IPLists) (MIT), as of 22 November 2026 (`curated/vpn-ipv4.txt`, `curated/vpn-ipv6-txt.txt`).
- Sightings reported by ProxyShield servers: kept 14 days under a hash of the install id, an address
  counts as `community` from 3 different servers.

`refresh.py` downloads and rebuilds all of it nightly and keeps the old file when a source fails.
It also writes a consistent copy of the database to `backup/` and keeps the last seven.

## Quality check

After every refresh, a list of real home and mobile addresses (kept on the server, not in the repository) is looked up in the new data. If the update flags one that the previous data did not, the previous data come back, the status says so and `/healthz` fails.

## Privacy by construction

- No access logs. Lookups are answered from the data and not stored.
- Statistics are two daily sums (lookups answered, lookups with a verdict), never an address,
  sender or time of a single lookup.
- Reporting is off by default in ProxyShield and has to be switched on by the server owner.

## Run it yourself

```
INTEL_DATA=./data python3 refresh.py
INTEL_DATA=./data python3 -c "from app import create_app; create_app().run(port=5191)"
```

The network feed is built by `rust/feedbuild` (static binary, `bin/feedbuild` on the server, about 3.5 s and 130 MB instead of 13 s and 375 MB); `feedbuild.py` is the fallback and produces the same file.

Tests: `python3 -m unittest discover -s tests`

Add address lists with a small window: `python3 tools/list_manager.py` (loads files or pasted text, keeps only what the service does not flag yet, writes `curated/<name>.txt`, can deploy and push).

Deploy to your own server: copy `deploy/local.env.example` to `deploy/local.env`, fill it in and run
`deploy/deploy.sh` (user, DNS record, TLS certificate, nginx, systemd units and the nightly timer).

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). If you run a changed copy as a service, the changed
source has to be offered to its users.
