# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy
from scapy.all import *

TYPE_TUNNEL = 0x1212
TYPE_IPV4   = 0x0800

class TunnelH(Packet):
   
    name = "TunnelH"
    fields_desc = [
        ShortField("tunnel_id", 0),
        ShortField("stack_len", 0),
        IntField("rsvd", 0)
    ]
    def mysummary(self):
        return self.sprintf("tunnel_id=%tunnel_id%, stack_len=%stack_len%")

class ValidationH(Packet):
   
    name = "ValidationH"
    fields_desc = [
        ShortField("hop_value", 0),
        ShortField("rsvd", 0)
    ]
    def mysummary(self):
        return self.sprintf("hop_value=%hop_value%")

bind_layers(Ether, TunnelH, type=TYPE_TUNNEL)
bind_layers(TunnelH, IP)


