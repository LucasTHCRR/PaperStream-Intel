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

from datasets import Datasets

LOOKUPS_PER_MINUTE = 600
STALE_HOURS = 48
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

    def client():
        address = request.remote_addr or ""
        if address == "127.0.0.1":
            address = request.headers.get("X-Real-IP") or address
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

    def count(flagged):
        with lock:
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

    def answer(text):
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return jsonify(error="not an IP address"), 422
        if not address.is_global:
            return jsonify(ip=str(address), country=None, asn=None, network="private", vpn=False, proxy=False,
                           tor=False, hosting=False, seen_by=0, community=False)
        result = datasets().lookup(address)
        seen = sightings(str(address))
        result.update(seen_by=seen, community=seen >= COMMUNITY_SERVERS)
        count(any(result[key] for key in ("vpn", "proxy", "tor", "hosting")) or result["community"])
        return jsonify(result)

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
            address = request.headers.get("X-Real-IP") or address
        return answer(address)

    @app.get("/healthz")
    def healthz():
        ages = {}
        for name in ("asn-feed.tsv.gz", "vpn.txt", "operators.txt"):
            path = sets_dir / name
            ages[name] = round((time.time() - path.stat().st_mtime) / 3600, 1) if path.exists() else None
        stale = [name for name, age in ages.items() if age is None or age > STALE_HOURS]
        status = 503 if stale else 200
        return jsonify(ok=not stale, stale=stale, age_hours=ages), status

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
