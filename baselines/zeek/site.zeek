# Site definition shared by both configurations.
# 192.168.10.0/24 is the CICIDS2017 victim LAN; the attacker 172.16.0.1 (NAT address) must count as external.
redef Site::local_nets += { 192.168.10.0/24 };
