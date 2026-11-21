"""Render evidence viewers and a short report from measured Suricata logs."""
import base64
import collections
import hashlib
import html
import json
from pathlib import Path
import subprocess

L = Path(__file__).resolve().parent.parent
E, R = L/'evidence', L/'report'
S = json.loads((E/'summary.json').read_text())
names = {'1000001':'ICMP echo', '1000002':'HTTP test marker', '1000003':'Login requests',
         '1000004':'HTTP policy', '1000005':'SYN burst / test ports'}
checks = {}
for phase in ['baseline','tuned','replay-tuned','ips']:
    events = [json.loads(line) for line in (E/phase/'eve.json').read_text().splitlines()]
    counts = collections.Counter(str(x['alert']['signature_id']) for x in events if x['event_type']=='alert')
    assert dict(sorted(counts.items())) == S['alerts'][phase]
    stats = [x['stats'] for x in events if x['event_type']=='stats'][-1]
    checks[phase] = {'alerts':sum(counts.values()), 'kernel_drops':stats.get('capture',{}).get('kernel_drops'),
                     'invalid_checksums':stats['tcp']['invalid_checksum'], 'rules_loaded':stats['detect']['engines'][0]['rules_loaded']}
    if phase in ['baseline','tuned']:
        assert stats['capture']['kernel_drops'] == 0
    assert stats['tcp']['invalid_checksum'] == 0
    assert stats['detect']['engines'][0]['rules_loaded'] == 5
assert S['alerts']['tuned'] == S['alerts']['replay-tuned']
for phase in ['baseline','tuned']:
    traffic = [json.loads(line) for line in (E/phase/'traffic.jsonl').read_text().splitlines()]
    assert sum(x.get('status')==200 for x in traffic)==17
    assert sum('scan_port' in x for x in traffic)==20
    assert '0% packet loss' in (E/phase/'ping.txt').read_text()
    assert S['alerts'][phase]['1000002']==1
ips_alerts = json.loads((E/'ips/alerts.json').read_text())
assert any(x['alert']['signature_id']==1000002 and x['alert']['action']=='blocked' for x in ips_alerts)
requests = [json.loads(line) for line in (E/'server.jsonl').read_text().splitlines()]
assert sum(x['path']=='/lab-attack' for x in requests)==2, 'Blocked marker reached server'
assert sum(x['path']=='/health' for x in requests)==22
checks['same_capture_replay_matches_live_tuned'] = True
checks['blocked_marker_absent_at_server'] = True
(E/'verification.json').write_text(json.dumps(checks,indent=2)+'\n')

browser_profile = L/'runtime/browser-profile'
def chrome(*args):
    result = subprocess.run(['chromium','--headless','--disable-gpu','--no-first-run',
        '--no-default-browser-check','--disable-dev-shm-usage',f'--user-data-dir={browser_profile}',
        *map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
    with (E/'render.log').open('a') as output:
        output.write(result.stdout)
    result.check_returncode()

for phase, title in [('baseline','Before tuning'),('tuned','After tuning')]:
    records = json.loads((E/phase/'alerts.json').read_text())
    count = S['alerts'][phase]
    marker = next(x for x in records if x['alert']['signature_id']==1000002)
    rows = ''.join(f'<tr><td>{sid}</td><td>{label}</td><td>{count.get(sid,0)}</td></tr>' for sid,label in names.items())
    sample = f"{marker['timestamp']} | SID 1000002 | {marker['src_ip']} → {marker['dest_ip']} | {marker['alert']['action']}"
    page = f'''<!doctype html><meta charset="utf-8"><title>{title} — Suricata evidence</title>
<style>*{{box-sizing:border-box}}body{{margin:0;padding:18px 26px;background:#f4f7fb;color:#162238;font:18px Arial}}h1{{font-size:23px;margin:0 0 5px}}p{{margin:5px 0;font-size:15px}}table{{border-collapse:collapse;width:100%;background:white;margin:10px 0}}td,th{{padding:5px 12px;text-align:left;border-bottom:1px solid #e0e5ed}}th{{font-size:15px;color:#52627a}}td:last-child{{font-weight:bold}}footer{{font:12px monospace;background:#e5edf8;padding:7px}}</style>
<h1>{title} · {sum(count.values())} alerts</h1><p>Suricata 7.0.10 · live IDS on gateway-b / b-lan · 5 loaded rules · 0 capture drops</p>
<table><tr><th>Signature ID</th><th>Observed alert category</th><th>Count</th></tr>{rows}</table>
<footer>Source: evidence/{phase}/eve.json<br>{html.escape(sample)}</footer>'''
    (R/f'{phase}-viewer.html').write_text(page)
    chrome('--hide-scrollbars','--window-size=900,340',f'--screenshot={R/("before.png" if phase=="baseline" else "after.png")}',(R/f'{phase}-viewer.html').as_uri())

before = sum(S['alerts']['baseline'].values())
after = sum(S['alerts']['tuned'].values())
reduction = (before-after)/before*100
text = f'''# Site-to-Site VPN and IDS/IPS Lab

**Date:** {S['executed_at_utc'][:10]} · **Environment:** isolated Linux network namespaces.

**Configuration.** WireGuard linked Site A `10.10.0.0/24` and Site B `10.20.0.0/24` over WAN `192.0.2.1–192.0.2.2`, using UDP 51820, tunnel `10.255.0.0/30`, MTU 1420, peer keys and subnet routes. Gateways enabled IPv4 forwarding and allowed only intersite forwarding. Suricata 7.0.10 inspected decrypted traffic on Site B's LAN with five local rules; both LANs were included in `HOME_NET`.

**Traffic.** Each IDS run sent 12 pings, 10 `/health`, five `/login`, one `/admin`, one harmless `/lab-attack` HTTP request, and connection attempts to 20 closed TCP ports (20000–20019).

**Alerts and tuning.** Alerts fell from **{before} to {after} ({reduction:.1f}% fewer)**. ICMP was limited to one alert/source/60 seconds; login alerts began after three requests/source/60 seconds; the broad GET rule was narrowed to `/admin`. The attack-marker and SYN-burst rules stayed active. The SYN rule detects a rate within the test port range, not unique ports; login requests do not prove failed authentication.

**Verification.** Both sites communicated; disabling the tunnel stopped intersite traffic. WAN captures contained encrypted UDP and no HTTP markers. Replaying the same baseline capture with tuned rules reproduced the tuned counts. All rules loaded; live IDS recorded zero capture drops and invalid TCP checksums. Inline NFQUEUE IPS logged the marker as `blocked`; its request timed out and never reached the server, while benign requests returned HTTP 200 before and after.

![Before tuning: recorded EVE alert counts](before.png)

![After tuning: recorded EVE alert counts](after.png)

*Screenshots show a browser viewer of actual saved EVE logs. Configs, commands, logs and packet captures are included beside this report. Processes/namespaces stopped after verification; lab files remain removable on request.*

**References:** [WireGuard setup](https://www.wireguard.com/quickstart/), [Suricata thresholds](https://docs.suricata.io/en/suricata-7.0.10/rules/thresholding.html), [Suricata inline IPS](https://docs.suricata.io/en/suricata-7.0.10/setting-up-ipsinline-for-linux.html).
'''
(R/'lab-report.md').write_text(text)
paragraphs = text.split('\n\n')
body = ''
for paragraph in paragraphs:
    if paragraph.startswith('# '):
        body += '<h1>'+html.escape(paragraph[2:])+'</h1>'
    elif paragraph.startswith('!['):
        filename = 'before.png' if 'before.png' in paragraph else 'after.png'
        data = base64.b64encode((R/filename).read_bytes()).decode()
        body += f'<img src="data:image/png;base64,{data}">'
    elif paragraph.startswith('**References:'):
        body += '<p class="small">References: <a href="https://www.wireguard.com/quickstart/">WireGuard setup</a> · <a href="https://docs.suricata.io/en/suricata-7.0.10/rules/thresholding.html">Suricata thresholds</a> · <a href="https://docs.suricata.io/en/suricata-7.0.10/setting-up-ipsinline-for-linux.html">Inline IPS</a></p>'
    else:
        escaped = html.escape(paragraph).replace('`','')
        parts = escaped.split('**')
        formatted = ''.join(('<b>'+part+'</b>') if i%2 else part for i,part in enumerate(parts))
        body += '<p>'+formatted.strip('*')+'</p>'
(R/'lab-report.html').write_text('''<!doctype html><meta charset="utf-8"><title>VPN and IDS/IPS Lab Report</title><style>
@page{size:A4;margin:12mm}body{font:9.3pt/1.28 Arial;color:#182433;margin:0}h1{font-size:17pt;margin:0 0 8px}p{margin:6px 0}img{display:block;width:100%;height:auto;margin:6px 0}.small{font-size:8pt}a{color:#285a85}</style>'''+body)
chrome('--no-pdf-header-footer',f'--print-to-pdf={R/"lab-report.pdf"}',(R/'lab-report.html').as_uri())
print(json.dumps({'baseline_alerts':before,'tuned_alerts':after,'reduction_percent':round(reduction,1),'verification':checks},indent=2))
