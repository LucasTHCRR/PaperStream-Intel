#!/bin/bash
# Spielt den Intel-Dienst auf den Root-Server und legt DNS-Eintrag, Zertifikat und den naechtlichen Abruf an.
# Mehrfach ausfuehrbar.
set -euo pipefail
HOST=root@45.133.74.209
KEY=~/.ssh/id_ed25519_45-133-74-209
DOMAIN=intel.paperstream.dev
SRC="$(cd "$(dirname "$0")/.." && pwd)"
SSH="ssh -i $KEY $HOST"

$SSH 'id paperstream-intel >/dev/null 2>&1 || useradd --system --home /var/lib/paperstream-intel --shell /usr/sbin/nologin paperstream-intel; mkdir -p /opt/paperstream-intel /var/lib/paperstream-intel; chown paperstream-intel: /var/lib/paperstream-intel; chmod 700 /var/lib/paperstream-intel'
tar -C "$SRC" --exclude=data --exclude=data-test --exclude=__pycache__ --exclude=tests --exclude=deploy -czf - . | $SSH 'tar -C /opt/paperstream-intel -xzf - && chown -R root:root /opt/paperstream-intel'
$SSH 'cd /opt/paperstream-intel && [ -d venv ] || python3 -m venv venv; venv/bin/pip install -q flask gunicorn'

# DNS: A-Eintrag ohne Cloudflare-Proxy (graue Wolke), wie bei paperstream.dev
$SSH "DOMAIN=$DOMAIN python3 - <<'PY'
import json, os, urllib.request
tok = open('/root/.secrets/cf-paperstream.token').read().strip()
def api(method, path, body=None):
    r = urllib.request.Request('https://api.cloudflare.com/client/v4' + path, method=method,
        data=json.dumps(body).encode() if body else None,
        headers={'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(r))
zone = api('GET', '/zones?name=paperstream.dev')['result'][0]['id']
name = os.environ['DOMAIN']
have = api('GET', f'/zones/{zone}/dns_records?name={name}&type=A')['result']
if have:
    print('dns: A record exists, proxied =', have[0]['proxied'])
else:
    r = api('POST', f'/zones/{zone}/dns_records', {'type': 'A', 'name': name, 'content': '45.133.74.209', 'proxied': False, 'ttl': 300})
    print('dns: created', r['success'])
PY"

# Zertifikat per DNS-Challenge, Erneuerung laeuft ueber den vorhandenen certbot-Timer
$SSH "[ -d /etc/letsencrypt/live/$DOMAIN ] || certbot certonly --non-interactive --agree-tos --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare-paperstream.ini --dns-cloudflare-propagation-seconds 40 -d $DOMAIN --deploy-hook 'systemctl reload nginx'"

scp -q -i $KEY "$SRC/deploy/paperstream-intel.service" $HOST:/etc/systemd/system/paperstream-intel.service
scp -q -i $KEY "$SRC/deploy/nginx-intel.conf" $HOST:/etc/nginx/sites-available/paperstream-intel.conf
$SSH 'ln -sf /etc/nginx/sites-available/paperstream-intel.conf /etc/nginx/sites-enabled/paperstream-intel.conf; nginx -t && systemctl reload nginx'
$SSH 'systemctl daemon-reload && systemctl enable paperstream-intel && systemctl restart paperstream-intel && sleep 2 && systemctl is-active paperstream-intel'

# Naechtlicher Datenabruf (Listen und Feed), beim ersten Mal sofort starten
scp -q -i $KEY "$SRC/deploy/paperstream-intel-refresh.service" "$SRC/deploy/paperstream-intel-refresh.timer" $HOST:/etc/systemd/system/
$SSH 'systemctl daemon-reload && systemctl enable --now paperstream-intel-refresh.timer'
$SSH '[ -f /var/lib/paperstream-intel/datasets/asn-feed.tsv.gz ] || systemctl start --no-block paperstream-intel-refresh.service'
echo "Erster Datenabruf laeuft im Hintergrund: journalctl -u paperstream-intel-refresh -f"
