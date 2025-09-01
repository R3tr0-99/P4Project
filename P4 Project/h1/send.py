#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy
import argparse, random, socket
from scapy.all import Ether, IP, TCP, Raw, get_if_hwaddr, get_if_list, sendp
from myTunnel_header import TYPE_TUNNEL, TunnelH, ValidationH

def get_if():
    for i in get_if_list():
        if "eth0" in i:
            return i
    raise RuntimeError("Cannot find eth0 interface")

def build_plain_ipv4(dst_ip, dscp, msg, iface):
    tos = (dscp & 0x3F) << 2   # DSCP sui 6 bit alti di diffserv; ECN=0
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
        IP(dst=dst_ip, tos=tos) /
        TCP(dport=1234, sport=random.randint(49152,65535)) /
        Raw(load=msg.encode())
    )
    return pkt

def build_manual_tunnel(dst_ip, tid, validations, msg, iface):
    # ✅ MAC destinazione fisso (esempio) o meglio: risolvi ARP
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="00:00:00:00:00:02", type=TYPE_TUNNEL) /
        TunnelH(tunnel_id=int(tid), stack_len=len(validations), rsvd=0)
    )
    
    for v in validations:
        pkt = pkt / ValidationH(hop_value=int(v), rsvd=0)
    
    pkt = pkt / IP(dst=dst_ip) / TCP(dport=1234, sport=random.randint(49152,65535)) / Raw(load=msg.encode())
    return pkt

def main():
    p = argparse.ArgumentParser()
    p.add_argument("ip_addr", type=str, help="Destination IP (e.g., 10.0.0.2)")
    p.add_argument("message", type=str, help="Payload message")
    p.add_argument("--dscp", type=int, default=0, help="DSCP 0..63 (usato dal P4 in ingress)")
    # Debug: costruzione manuale del tunnel (sconsigliata per i test finali)
    p.add_argument("--tid", type=int, default=None, help="Forza invio con TunnelH tunnel_id")
    p.add_argument("--validation", type=str, default="", help="Lista valori hop separati da virgola, es: '5,7'")
    args = p.parse_args()

    iface = get_if()
    dst_ip = socket.gethostbyname(args.ip_addr)

    if args.tid is None:
        print(f"[plain] iface={iface} dst={dst_ip} dscp={args.dscp}")
        pkt = build_plain_ipv4(dst_ip, args.dscp, args.message, iface)
    else:
        vals = [v for v in args.validation.split(",") if v != ""]
        print(f"[manual-tunnel] iface={iface} dst={dst_ip} tid={args.tid} stack_len={len(vals)}")
        pkt = build_manual_tunnel(dst_ip, args.tid, vals, args.message, iface)

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == "__main__":
    main()

