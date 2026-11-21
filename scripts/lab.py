"""Run real kernel VPN, live IDS, offline comparison and inline IPS in private namespaces."""
import collections
import datetime
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import yaml

LAB = Path('/lab')
E = LAB / 'evidence'
C = LAB / 'configs'
NAMES = ['site-a', 'gateway-a', 'gateway-b', 'site-b']
processes = []
log = (E / 'commands.log').open('w')

def run(args, ns=None, check=True, timeout=30):
    command = (['ip', 'netns', 'exec', ns] if ns else []) + list(map(str, args))
    log.write('$ ' + ' '.join(command) + '\n'); log.flush()
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    log.write(result.stdout + f'[exit {result.returncode}]\n'); log.flush()
    if check and result.returncode:
        raise RuntimeError(f'{command}: {result.stdout}')
    return result

def start(args, ns, filename):
    handle = (E / filename).open('w')
    command = ['ip', 'netns', 'exec', ns] + list(map(str, args))
    log.write('$ ' + ' '.join(command) + ' [background]\n'); log.flush()
    proc = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT)
    processes.append((proc, handle))
    return proc

def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()

def link(ns1, dev1, addr1, ns2, dev2, addr2):
    run(['ip', 'link', 'add', dev1, 'type', 'veth', 'peer', 'name', dev2])
    for ns, dev, addr in [(ns1, dev1, addr1), (ns2, dev2, addr2)]:
        run(['ip', 'link', 'set', dev, 'netns', ns])
        run(['ip', 'address', 'add', addr, 'dev', dev], ns)
        run(['ip', 'link', 'set', dev, 'up'], ns)
        run(['ethtool', '-K', dev, 'tx', 'off', 'rx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off'], ns, check=False)

def wait_sensor(proc, name):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f'Sensor {name} exited: {(E / (name+"/console.log")).read_text()}')
        path = E / name / 'suricata.log'
        if path.exists() and 'engine started' in path.read_text().lower():
            return
        time.sleep(.1)
    raise RuntimeError(f'Sensor {name} did not become ready')

def sensor(name, rules, ips=False):
    directory = E / name
    directory.mkdir(exist_ok=True)
    args = ['suricata', '-c', str(C / 'suricata.yaml'), '-S', str(C / rules),
            '-l', str(directory), '--runmode', 'autofp' if ips else 'single']
    args += ['-q', '0'] if ips else ['--pcap=b-lan']
    proc = start(args, 'gateway-b', name+'/console.log')
    wait_sensor(proc, name)
    return proc

def traffic(name):
    ping = run(['ping', '-c', '12', '-i', '.1', '-W', '1', '10.20.0.10'], 'site-a')
    (E / name / 'ping.txt').write_text(ping.stdout)
    result = run(['python3', str(LAB / 'scripts/traffic.py')], 'site-a', timeout=30)
    (E / name / 'traffic.jsonl').write_text(result.stdout)

def alerts(name):
    items = [json.loads(line) for line in (E/name/'eve.json').read_text().splitlines()]
    counts = collections.Counter(str(item['alert']['signature_id']) for item in items if item.get('event_type') == 'alert')
    details = [item for item in items if item.get('event_type') == 'alert']
    (E/name/'alerts.json').write_text(json.dumps(details, indent=2)+'\n')
    return dict(sorted(counts.items()))

try:
    E.mkdir(exist_ok=True); C.mkdir(exist_ok=True)
    for phase in ['baseline','tuned','replay-tuned','ips']:
        shutil.rmtree(E/phase, ignore_errors=True)
    for ns in NAMES:
        run(['ip', 'netns', 'add', ns])
        run(['ip', 'link', 'set', 'lo', 'up'], ns)
    link('site-a','a-host','10.10.0.10/24','gateway-a','a-lan','10.10.0.1/24')
    link('gateway-a','a-wan','192.0.2.1/30','gateway-b','b-wan','192.0.2.2/30')
    link('gateway-b','b-lan','10.20.0.1/24','site-b','b-host','10.20.0.10/24')
    run(['ip','route','add','default','via','10.10.0.1'], 'site-a')
    run(['ip','route','add','default','via','10.20.0.1'], 'site-b')
    keys = {}
    for side in ['a','b']:
        private = subprocess.check_output(['wg','genkey'], text=True).strip()
        public = subprocess.check_output(['wg','pubkey'], input=private+'\n', text=True).strip()
        path = Path('/run') / f'wg-{side}.key'
        path.write_text(private+'\n'); path.chmod(0o600)
        keys[side] = public
    for side, other, local, remote, lan, tunnel in [
        ('a','b','192.0.2.1','192.0.2.2','10.20.0.0/24','10.255.0.1'),
        ('b','a','192.0.2.2','192.0.2.1','10.10.0.0/24','10.255.0.2')]:
        ns = 'gateway-'+side
        run(['sysctl','-w','net.ipv4.ip_forward=1'], ns)
        run(['ip','link','add','wg0','type','wireguard'], ns)
        run(['ip','address','add',tunnel+'/30','dev','wg0'], ns)
        run(['wg','set','wg0','listen-port','51820','private-key','/run/wg-'+side+'.key',
             'peer',keys[other],'allowed-ips',lan+',10.255.0.'+('2' if side=='a' else '1')+'/32',
             'endpoint',remote+':51820'], ns)
        run(['ip','link','set','wg0','mtu','1420','up'], ns)
        run(['ip','route','add',lan,'dev','wg0'], ns)
        run(['iptables','-P','FORWARD','DROP'], ns)
        run(['iptables','-A','FORWARD','-i',side+'-lan','-o','wg0','-s',('10.10.0.0/24' if side=='a' else '10.20.0.0/24'),'-d',lan,'-j','ACCEPT'], ns)
        run(['iptables','-A','FORWARD','-i','wg0','-o',side+'-lan','-s',lan,'-d',('10.10.0.0/24' if side=='a' else '10.20.0.0/24'),'-j','ACCEPT'], ns)
        run(['iptables','-P','INPUT','DROP'], ns)
        run(['iptables','-A','INPUT','-i','lo','-j','ACCEPT'], ns)
        run(['iptables','-A','INPUT','-i',side+'-wan','-s',remote,'-p','udp','--dport','51820','-j','ACCEPT'], ns)
        run(['iptables','-A','INPUT','-i',side+'-lan','-p','icmp','-j','ACCEPT'], ns)
        run(['iptables','-A','INPUT','-i','wg0','-p','icmp','-j','ACCEPT'], ns)
        (C / f'gateway-{side}.conf.example').write_text(
            f'[Interface]\nPrivateKey = <ephemeral key generated at run time>\nAddress = {tunnel}/30\nListenPort = 51820\nMTU = 1420\n\n'
            f'[Peer]\nPublicKey = {keys[other]}\nAllowedIPs = {lan}, 10.255.0.{"2" if side=="a" else "1"}/32\nEndpoint = {remote}:51820\n')
    base = yaml.safe_load(Path('/etc/suricata/suricata.yaml').read_text())
    base['vars']['address-groups']['HOME_NET'] = '[10.10.0.0/24,10.20.0.0/24]'
    base['vars']['address-groups']['EXTERNAL_NET'] = 'any'
    base['stream']['checksum-validation'] = True
    base['stream']['inline'] = 'auto'
    base['stats']['interval'] = 1
    base['threading']['detect-thread-ratio'] = 0.1
    base['default-rule-path'] = str(C)
    base['rule-files'] = ['tuned.rules']
    base['pcap'] = [{'interface':'b-lan','checksum-checks':'yes','threads':1}]
    for entry in base['outputs']:
        if 'eve-log' in entry:
            entry['eve-log']['enabled'] = True
    (C/'suricata.yaml').write_text('%YAML 1.1\n---\n'+yaml.safe_dump(base,sort_keys=False))
    (E/'versions.txt').write_text(run(['suricata','--build-info']).stdout+run(['wg','--version']).stdout+run(['apk','info','-vv']).stdout)
    for rules in ['baseline.rules','tuned.rules','ips.rules']:
        result = run(['suricata','-T','-c',str(C/'suricata.yaml'),'-S',str(C/rules)])
        (E / ('validate-'+rules+'.txt')).write_text(result.stdout)
    server = start(['python3',str(LAB/'scripts/server.py')], 'site-b', 'server.jsonl')
    time.sleep(.3)
    run(['ping','-c','3','-W','1','10.20.0.10'], 'site-a')
    run(['ping','-c','3','-W','1','10.10.0.10'], 'site-b')
    run(['ip','link','set','wg0','down'], 'gateway-a')
    negative = run(['ping','-c','2','-W','1','10.20.0.10'], 'site-a', check=False)
    (E/'vpn-down.txt').write_text(negative.stdout)
    assert negative.returncode != 0, 'Traffic bypassed VPN'
    run(['ip','link','set','wg0','up'], 'gateway-a')
    run(['ip','route','replace','10.20.0.0/24','dev','wg0'], 'gateway-a')
    for phase, rules in [('baseline','baseline.rules'),('tuned','tuned.rules')]:
        (E/phase).mkdir(exist_ok=True)
        capture = start(['tcpdump','-U','-n','-i','b-lan','-w',str(E/phase/'inner.pcap')], 'gateway-b',phase+'/capture.log')
        outer = start(['tcpdump','-U','-n','-i','b-wan','-w',str(E/phase/'outer.pcap')], 'gateway-b',phase+'/wan-capture.log')
        proc = sensor(phase,rules)
        traffic(phase)
        time.sleep(2)
        stop(proc); stop(capture); stop(outer)
    (E/'replay-tuned').mkdir(exist_ok=True)
    run(['suricata','-c',str(C/'suricata.yaml'),'-S',str(C/'tuned.rules'),'-r',str(E/'baseline/inner.pcap'),'-l',str(E/'replay-tuned'),'--runmode','single'])
    (E/'ips').mkdir(exist_ok=True)
    proc = sensor('ips','ips.rules',True)
    run(['iptables','-I','FORWARD','1','-i','wg0','-o','b-lan','-j','NFQUEUE','--queue-num','0'], 'gateway-b')
    run(['iptables','-I','FORWARD','1','-i','b-lan','-o','wg0','-j','NFQUEUE','--queue-num','0'], 'gateway-b')
    good = run(['curl','--noproxy','*','--max-time','3','-sS','-o','/dev/null','-w','%{http_code}','http://10.20.0.10:8080/health'], 'site-a')
    bad = run(['curl','--noproxy','*','--max-time','3','-sS','-o','/dev/null','-w','%{http_code}','http://10.20.0.10:8080/lab-attack'], 'site-a', check=False)
    after = run(['curl','--noproxy','*','--max-time','3','-sS','-o','/dev/null','-w','%{http_code}','http://10.20.0.10:8080/health'], 'site-a')
    (E/'ips/http-results.json').write_text(json.dumps({'before':good.stdout,'blocked_exit':bad.returncode,'blocked_output':bad.stdout,'after':after.stdout},indent=2)+'\n')
    assert good.stdout == after.stdout == '200' and bad.returncode != 0
    time.sleep(2)
    (E/'ips/firewall.txt').write_text(run(['iptables','-vnL','FORWARD'], 'gateway-b').stdout)
    stop(proc)
    stop(server)
    for side in ['a','b']:
        (E/f'gateway-{side}-state.txt').write_text(run(['wg','show'], 'gateway-'+side).stdout+run(['ip','-brief','address'], 'gateway-'+side).stdout+run(['ip','route'], 'gateway-'+side).stdout+run(['iptables-save'], 'gateway-'+side).stdout)
    for phase in ['baseline','tuned']:
        (E/phase/'outer-decoded.txt').write_text(run(['tcpdump','-nn','-r',str(E/phase/'outer.pcap')]).stdout)
        (E/phase/'inner-decoded.txt').write_text(run(['tcpdump','-nn','-A','-r',str(E/phase/'inner.pcap')]).stdout)
        outer_data = (E/phase/'outer.pcap').read_bytes()
        assert b'/lab-attack' not in outer_data and b'/health' not in outer_data
        assert b'/lab-attack' in (E/phase/'inner.pcap').read_bytes()
    summary = {'executed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'alerts':{name:alerts(name) for name in ['baseline','tuned','replay-tuned','ips']},
               'checks':{'bidirectional_vpn':True,'no_vpn_bypass':True,'wan_payload_hidden':True,'inner_payload_visible':True,'ips_blocked_marker':True,'ips_benign_before_after':True}}
    (E/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2),flush=True)
finally:
    for proc, handle in reversed(processes):
        stop(proc); handle.close()
    for ns in reversed(NAMES):
        run(['ip','netns','del',ns], check=False)
    log.close()
