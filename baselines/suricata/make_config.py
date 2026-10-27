"""Create suricata_alerts_only.yaml from the Homebrew default: HOME_NET = the CICIDS victim LAN, eve.json = alerts only."""
import re
src = '/opt/homebrew/etc/suricata/suricata.yaml'
lines = open(src).read().split('\n')
out, i = [], 0
while i < len(lines):
    ln = lines[i]
    if re.match(r'^    HOME_NET: ', ln):
        # CIC's victim network. The default also lists 172.16.0.0/12, which would put the NAT'd attacker (172.16.0.1) inside HOME_NET.
        ln = '    HOME_NET: "[192.168.10.0/24]"'
    if re.match(r'^        - frame:', ln):          # drop every eve type after 'alert'
        i += 1
        while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith('#') or len(lines[i]) - len(lines[i].lstrip()) >= 8):
            i += 1
        continue
    out.append(ln)
    i += 1
open('suricata_alerts_only.yaml', 'w').write('\n'.join(out))
print('wrote suricata_alerts_only.yaml')
