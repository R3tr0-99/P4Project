#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy
import os, sys, struct
from scapy.all import Ether, IP, TCP, Raw, sniff
from myTunnel_header import TYPE_TUNNEL, TunnelH, ValidationH

def get_iface():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    if not ifaces:
        raise RuntimeError("No eth interface found")
    return ifaces[0]

def parse_validation_stack(pkt):
 
    th = pkt[TunnelH]
    stack_len = int(th.stack_len)
    # Calcola offset del payload subito dopo TunnelH
    raw = bytes(pkt[Raw]) if Raw in pkt else b""
    vals = []
    need = stack_len * 4
    if len(raw) < need:
        return vals, 0  # pacchetto tronco o parsing non riuscito
    for i in range(stack_len):
        hop_value, rsvd = struct.unpack("!HH", raw[i*4:(i+1)*4])
        vals.append(hop_value)
    return vals, sum(vals)

def handle_pkt(pkt):
    eth = pkt[Ether]
    if eth.type == TYPE_TUNNEL and TunnelH in pkt:
        vals, s = parse_validation_stack(pkt)  # ✅ Usa parsing manuale
        t = pkt[TunnelH]
        print(f"[TUNNEL] tid={t.tunnel_id} stack_len={t.stack_len} values={vals} sum={s}")
        if IP in pkt:
            ip = pkt[IP]
            print(f"        inner IP: {ip.src} -> {ip.dst} dscp={(ip.tos >> 2)} ttl={ip.ttl}")
    elif IP in pkt and TCP in pkt and pkt[TCP].dport == 1234:
        ip = pkt[IP]
        print(f"[IP] {ip.src} -> {ip.dst} dscp={(ip.tos >> 2)} ttl={ip.ttl}")
    else:
        return
    pkt.show2()
    sys.stdout.flush()

def main():
    iface = get_iface()
    print(f"sniffing on {iface}")
    sys.stdout.flush()
    sniff(iface=iface, prn=handle_pkt, store=False)

if __name__ == "__main__":
    main()

