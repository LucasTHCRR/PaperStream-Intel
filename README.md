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
GET  /healthz                 200 while every dataset is fresh, 503 with the stale files otherwise
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
- Sightings reported by ProxyShield servers: kept 14 days under a hash of the install id, an address
  counts as `community` from 3 different servers.

`refresh.py` downloads and rebuilds all of it nightly and keeps the old file when a source fails.
It also writes a consistent copy of the database to `backup/` and keeps the last seven.

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

Tests: `python3 -m unittest discover -s tests`

Deploy to your own server: copy `deploy/local.env.example` to `deploy/local.env`, fill it in and run
`deploy/deploy.sh` (user, DNS record, TLS certificate, nginx, systemd units and the nightly timer).

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). If you run a changed copy as a service, the changed
source has to be offered to its users.
