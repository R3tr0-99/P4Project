# P4 Tunnel-Based Forwarding with Proof of Transit

# Objective
Design and implement a P4-based network pipeline that forwards packets using a custom tunnel identifier instead of the destination IP address. The system adds a path validation mechanism where each transit switch contributes to a stack of headers, and the egress switch verifies the integrity of the path before accepting or dropping the packet.

# Headers

*tunnel_h*: Used for forwarding. Contains a tunnel_id and a validation stack.

*validation_h*: Appended by each transit switch. Contains a hop-specific value.

# Ingress Switch

Classifies packets based on IPv4 src, dst, and DSCP to select a tunnel_id.

Pushes the tunnel_h header with the selected ID.

Initializes the validation stack by pushing the first validation_h header.

# Transit Switches

Forward packets based on the tunnel_id in the tunnel_h header.

Append a validation_h header to the stack with a configurable, hop-specific value.

# Egress Switch

Processes the validation stack and sums all the hop values.

Compares the calculated sum to a pre-configured threshold for the specific tunnel_id.

If the sum is greater than or equal to the threshold, the packet is forwarded to its final destination (based on its inner IPv4 header).

If the sum is below the threshold, the packet is dropped.

# Purpose
This implementation ensures that a packet has traversed the intended path of switches (providing Proof of Transit) before being delivered, enhancing network security and control.
