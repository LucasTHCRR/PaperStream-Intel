# SPDX-License-Identifier: AGPL-3.0-or-later
"""PaperStream intel service: free address lookups for anti-VPN plugins, the network feed, and an opt-in
sightings counter fed by ProxyShield servers that chose to report."""
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import sqlite3
import threading
import time

from flask import redirect, Flask, Response, jsonify, request, send_file

from datasets import Datasets, SCORES, score

LOOKUPS_PER_MINUTE = 600
STALE_HOURS = 48
BULK_MAX = 50
REPORTS_PER_MINUTE = 30
REPORT_BATCH = 200
REPORTS_PER_DAY = 2000
RETENTION_DAYS = 14
COMMUNITY_SERVERS = 3
INSTALL = re.compile(r"^[0-9a-f]{32,64}$")


def create_app(data_dir=None, datasets_dir=None):
    data = pathlib.Path(data_dir or os.environ.get("INTEL_DATA", "data"))
    data.mkdir(parents=True, exist_ok=True)
    sets_dir = pathlib.Path(datasets_dir or data / "datasets")
    sets_dir.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    state = {"datasets": Datasets(sets_dir), "stamp": 0.0, "checked": 0.0, "purged": 0.0}
    salt = secrets.token_bytes(16)
    windows = {}
    lock = threading.Lock()
    db = sqlite3.connect(data / "intel.db", check_same_thread=False)
    db.execute("CREATE TABLE IF NOT EXISTS sightings (ip TEXT NOT NULL, install TEXT NOT NULL, day INTEGER NOT NULL,"
               " PRIMARY KEY (ip, install))")
    db.execute("CREATE INDEX IF NOT EXISTS sightings_day ON sightings (day)")
    db.execute("CREATE TABLE IF NOT EXISTS daily (day INTEGER NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL,"
               " PRIMARY KEY (day, kind))")
    db.commit()

    def stamp():
        files = [p for p in sets_dir.iterdir() if p.is_file()]
        return max((p.stat().st_mtime for p in files), default=0.0)

    state["stamp"] = stamp()

    def datasets():
        now = time.time()
        if now - state["checked"] > 60:
            state["checked"] = now
            latest = stamp()
            if latest != state["stamp"]:
                state["datasets"] = Datasets(sets_dir)
                state["stamp"] = latest
        return state["datasets"]

    def forwarded():
        # Hinter dem Cloudflare-Tunnel steht die Adresse in CF-Connecting-IP, nur mit INTEL_TRUST_CF=1 beachten
        if os.environ.get("INTEL_TRUST_CF") == "1" and request.headers.get("CF-Connecting-IP"):
            return request.headers["CF-Connecting-IP"]
        return request.headers.get("X-Real-IP")

    def client():
        address = request.remote_addr or ""
        if address == "127.0.0.1":
            address = forwarded() or address
        return hashlib.sha256(salt + address.encode()).hexdigest()

    def limited(kind, limit):
        minute = int(time.time() // 60)
        key = (kind, client())
        with lock:
            if len(windows) > 50000:
                windows.clear()
            seen_minute, count = windows.get(key, (minute, 0))
            if seen_minute != minute:
                count = 0
            windows[key] = (minute, count + 1)
            return count + 1 > limit

    def too_many():
        response = jsonify(error="rate limited")
        response.status_code = 429
        response.headers["Retry-After"] = "60"
        return response

    def today():
        return int(time.time() // 86400)

    def sightings(ip):
        with lock:
            row = db.execute("SELECT COUNT(*) FROM sightings WHERE ip = ? AND day >= ?",
                             (ip, today() - RETENTION_DAYS)).fetchone()
        return row[0]

    counts = {"requests": 0, "flagged": 0, "flushed": time.time()}
    minutes = {}

    def count(flagged):
        with lock:
            minute = int(time.time() // 60)
            minutes[minute] = minutes.get(minute, 0) + 1
            for old in [m for m in minutes if m < minute - 10]:
                del minutes[old]
            counts["requests"] += 1
            counts["flagged"] += 1 if flagged else 0
            if time.time() - counts["flushed"] < 60:
                return
            day = today()
            for kind in ("requests", "flagged"):
                if counts[kind]:
                    db.execute("INSERT INTO daily (day, kind, n) VALUES (?, ?, ?) ON CONFLICT (day, kind) DO UPDATE SET n = n + ?",
                               (day, kind, counts[kind], counts[kind]))
                    counts[kind] = 0
            db.commit()
            counts["flushed"] = time.time()

    def totals(days=None):
        """Sums over the last `days` days (today included), or over everything."""
        first = today() - days + 1 if days else 0
        with lock:
            rows = db.execute("SELECT kind, SUM(n), MIN(day) FROM daily WHERE day >= ? GROUP BY kind", (first,)).fetchall()
            pending = dict(counts)
        found = {kind: (total, start) for kind, total, start in rows}
        start_day = min((start for _, start in found.values()), default=today())
        result = {"requests": found.get("requests", (0, 0))[0] + pending["requests"],
                  "flagged": found.get("flagged", (0, 0))[0] + pending["flagged"],
                  "since": time.strftime("%Y-%m-%d", time.gmtime(start_day * 86400))}
        if days:
            result["days"] = days
        return result

    def series(days):
        first = today() - days + 1
        with lock:
            rows = db.execute("SELECT day, kind, n FROM daily WHERE day >= ?", (first,)).fetchall()
            pending = dict(counts)
        table = {first + offset: {"requests": 0, "flagged": 0} for offset in range(days)}
        for day, kind, n in rows:
            if day in table:
                table[day][kind] = n
        for kind in ("requests", "flagged"):
            table[today()][kind] += pending[kind]
        return [{"date": time.strftime("%Y-%m-%d", time.gmtime(day * 86400)), **values} for day, values in sorted(table.items())]

    def days_argument(default=None):
        try:
            value = int(request.args.get("days", ""))
        except ValueError:
            return default
        return max(1, min(value, 3650))

    def operator_counts():
        path = sets_dir / "operators.json"
        try:
            return {name: len(addresses) for name, addresses in json.loads(path.read_text()).items()}
        except (OSError, ValueError):
            return {}

    def purge():
        now = time.time()
        if now - state["purged"] > 3600:
            state["purged"] = now
            db.execute("DELETE FROM sightings WHERE day < ?", (today() - RETENTION_DAYS,))
            db.commit()

    @app.after_request
    def headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    def index():
        return redirect("https://paperstream.dev/api", code=302)

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.get("/v1/stats")
    def stats():
        with lock:
            count = db.execute("SELECT COUNT(DISTINCT ip) FROM sightings WHERE day >= ?",
                               (today() - RETENTION_DAYS,)).fetchone()[0]
        return jsonify(dict(datasets().summary(), reported_addresses=count, operators=operator_counts(),
                            answered=totals(days_argument())))

    @app.get("/v1/stats/daily")
    def stats_daily():
        """Answered lookups per day for the last `days` days (default 30), for filters and charts."""
        return jsonify(series(days_argument(30)))

    def verdict(text):
        """The answer for one address, or None if the text is not an address."""
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return None
        if not address.is_global:
            return dict(ip=str(address), country=None, asn=None, network="private", vpn=False, proxy=False,
                        tor=False, hosting=False, reasons=[], score=0, seen_by=0, community=False)
        result = datasets().lookup(address)
        seen = sightings(str(address))
        community = seen >= COMMUNITY_SERVERS
        if community:
            result["reasons"] = sorted(result["reasons"] + ["reported-by-servers"], key=lambda name: -SCORES[name])
            result["score"] = score(result["reasons"])
        result.update(seen_by=seen, community=community)
        count(any(result[key] for key in ("vpn", "proxy", "tor", "hosting")) or result["community"])
        return result

    def answer(text):
        result = verdict(text)
        if result is None:
            return jsonify(error="not an IP address"), 422
        return jsonify(result)

    @app.post("/v1/bulk")
    def bulk():
        """Up to 50 addresses in one request, each counts as a lookup for the rate limit."""
        body = request.get_json(silent=True)
        ips = body.get("ips") if isinstance(body, dict) else None
        if not isinstance(ips, list) or not ips or len(ips) > BULK_MAX or not all(isinstance(x, str) for x in ips):
            return jsonify(error=f"send {{\"ips\": [...]}} with 1 to {BULK_MAX} addresses"), 422
        for _ in ips:
            if limited("lookup", LOOKUPS_PER_MINUTE):
                return too_many()
        results = []
        for text in ips:
            result = verdict(text.strip())
            results.append(result if result is not None else {"ip": text, "error": "not an IP address"})
        return jsonify(results=results)

    @app.get("/v1/ip/<text>")
    def lookup(text):
        if limited("lookup", LOOKUPS_PER_MINUTE):
            return too_many()
        return answer(text)

    @app.get("/v1/me")
    def me():
        """The verdict on the address that asks, for the website's "Your IP" button. Nothing is stored."""
        if limited("lookup", LOOKUPS_PER_MINUTE):
            return too_many()
        address = request.remote_addr or ""
        if address == "127.0.0.1":
            address = forwarded() or address
        return answer(address)

    def load():
        """Numbers for the operator: lookups per minute, memory of the service and of the machine."""
        minute = int(time.time() // 60)
        with lock:
            last = minutes.get(minute - 1, 0)
            five = sum(minutes.get(minute - offset, 0) for offset in range(1, 6))
        info = {"requests_last_minute": last, "requests_last_5_minutes": five}
        try:
            for line in open("/proc/self/status"):
                if line.startswith("VmRSS:"):
                    info["service_memory_mb"] = int(line.split()[1]) // 1024
            for line in open("/proc/meminfo"):
                if line.startswith("MemAvailable:"):
                    info["memory_available_mb"] = int(line.split()[1]) // 1024
            info["load_1m"] = round(os.getloadavg()[0], 2)
            info["cpus"] = os.cpu_count() or 1
        except (OSError, ValueError):
            pass
        return info

    # Zeitweise Diagnose (INTEL_DIAG=1): nur Zaehler pro Endpunkt und Programmname, keine Adressen, keine Zeiten
    if os.environ.get("INTEL_DIAG") == "1":
        diag = {}

        @app.after_request
        def count_clients(response):
            path = request.path
            kind = "ip" if path.startswith("/v1/ip/") else path if path in ("/v1/me", "/healthz", "/v1/stats", "/v1/stats/daily", "/v1/report") else "other"
            family = (request.headers.get("User-Agent") or "none").split("/")[0].split(" ")[0][:30]
            with lock:
                diag[(kind, family)] = diag.get((kind, family), 0) + 1
            return response

        @app.get("/internal/diag")
        def show_diag():
            if request.headers.get("X-Real-IP") or request.headers.get("CF-Connecting-IP") or request.remote_addr != "127.0.0.1":
                return jsonify(error="not found"), 404
            with lock:
                rows = sorted(diag.items(), key=lambda item: -item[1])
            return jsonify([{"endpoint": k[0], "client": k[1], "count": n} for k, n in rows])

    def canary_status():
        """Result of the last check with known good addresses (written by refresh.py), None if there is none."""
        try:
            return json.loads((data / "canary.json").read_text())
        except (OSError, ValueError):
            return None

    @app.get("/healthz")
    def healthz():
        ages = {}
        for name in ("asn-feed.tsv.gz", "vpn.txt", "operators.txt"):
            path = sets_dir / name
            ages[name] = round((time.time() - path.stat().st_mtime) / 3600, 1) if path.exists() else None
        stale = [name for name, age in ages.items() if age is None or age > STALE_HOURS]
        canary = canary_status()
        if canary and not canary.get("ok", True):
            stale.append("canary")
        status = 503 if stale else 200
        return jsonify(ok=not stale, stale=stale, age_hours=ages, load=load(),
                       canary=None if canary is None else {k: canary.get(k) for k in ("ok", "checked", "flagged", "rolled_back")}), status

    started_at = int(time.time())
    counted = {}

    def line_count(name):
        path = sets_dir / name
        try:
            stamp = path.stat().st_mtime
        except OSError:
            return None
        cached = counted.get(name)
        if cached and cached[0] == stamp:
            return cached[1]
        with path.open("rb") as handle:
            count = sum(1 for line in handle if line.strip() and not line.startswith(b"#"))
        counted[name] = (stamp, count)
        return count

    @app.get("/v1/status")
    def public_status():
        """What the status page shows: how fresh the data are, how big, and whether the quality check passed."""
        sources = [
            ("Network feed", "asn-feed.tsv.gz", "iptoasn.com, APNIC", None),
            ("VPN and datacenter lists", "vpn.txt", "X4BNet lists_vpn", None),
            ("VPN operator relays", "operators.txt", "Mullvad, IVPN, NordVPN, PIA, Surfshark", None),
            ("Cloud provider ranges", "clouds.txt", "AWS, Google Cloud, Oracle, DigitalOcean", None),
            ("Hosting ranges from the registries", "rir-hosting.txt", "RIPE, APNIC, AFRINIC, LACNIC", None),
            ("Community VPN lists", "community.txt", "Joe12387, tn3w, az0", None),
            ("Tor exit nodes", "tor.txt", "Tor Project", None),
            ("Open proxies", "proxy.txt", "monosans", None),
        ]
        rows = []
        for title, name, origin, _ in sources:
            path = sets_dir / name
            age = round((time.time() - path.stat().st_mtime) / 3600, 1) if path.exists() else None
            rows.append({"name": title, "origin": origin, "age_hours": age,
                         "entries": None if name == "asn-feed.tsv.gz" else line_count(name)})
        summary = datasets().summary()
        rows[0]["entries"] = summary.get("feed_ranges")
        canary = canary_status()
        stale = [r["name"] for r in rows if r["age_hours"] is None or r["age_hours"] > STALE_HOURS * 2]
        return jsonify(ok=not stale and (canary is None or canary.get("ok", True)), up_since=started_at,
                       data=rows, feed_built=summary.get("feed_built"),
                       canary=None if canary is None else {"checked": canary.get("checked"), "flagged": canary.get("flagged"),
                                                           "ok": canary.get("ok"), "checked_at": canary.get("checked_at")})

    @app.get("/feed/asn-feed.tsv.gz")
    def feed():
        path = sets_dir / "asn-feed.tsv.gz"
        if not path.exists():
            return jsonify(error="feed not built yet"), 404
        return send_file(path, mimetype="application/gzip", conditional=True, max_age=3600)

    @app.get("/feed/operators.txt")
    def operators():
        path = sets_dir / "operators.txt"
        if not path.exists():
            return jsonify(error="not built yet"), 404
        return send_file(path, mimetype="text/plain", conditional=True, max_age=3600)

    def install_id(body):
        value = body.get("install") if isinstance(body, dict) else None
        if not isinstance(value, str) or not INSTALL.match(value):
            return None
        return hashlib.sha256(value.encode()).hexdigest()

    @app.post("/v1/report")
    def report():
        if limited("report", REPORTS_PER_MINUTE):
            return too_many()
        body = request.get_json(silent=True)
        install = install_id(body)
        ips = body.get("ips") if isinstance(body, dict) else None
        if install is None or not isinstance(ips, list) or len(ips) > REPORT_BATCH:
            return jsonify(error="expected install id and up to %d addresses" % REPORT_BATCH), 400
        accepted = []
        for text in ips:
            try:
                address = ipaddress.ip_address(text)
            except (ValueError, TypeError):
                continue
            if address.is_global:
                accepted.append(str(address))
        with lock:
            used = db.execute("SELECT COUNT(*) FROM sightings WHERE install = ? AND day = ?",
                              (install, today())).fetchone()[0]
            if used + len(accepted) > REPORTS_PER_DAY:
                return too_many()
            db.executemany("INSERT INTO sightings (ip, install, day) VALUES (?, ?, ?)"
                           " ON CONFLICT(ip, install) DO UPDATE SET day = excluded.day",
                           [(ip, install, today()) for ip in accepted])
            db.commit()
            purge()
        return jsonify(accepted=len(accepted))

    @app.post("/v1/forget")
    def forget():
        if limited("report", REPORTS_PER_MINUTE):
            return too_many()
        install = install_id(request.get_json(silent=True))
        if install is None:
            return jsonify(error="expected install id"), 400
        with lock:
            deleted = db.execute("DELETE FROM sightings WHERE install = ?", (install,)).rowcount
            db.commit()
        return jsonify(deleted=deleted)

    app.db = db
    return app
