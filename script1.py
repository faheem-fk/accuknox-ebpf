from bcc import BPF
import psutil

# Get the configurable port number from user input
configurable_port = int(input("Enter the port number to drop packets on: "))

# List available network interfaces
interfaces = psutil.net_if_addrs()
print("Available Network Interfaces:")
for idx, interface in enumerate(interfaces.keys(), start=1):
    print(f"{idx}: {interface}")

# Get user input for the network interface
selected_interface_idx = int(input("Enter the number corresponding to the network interface: "))
selected_interface = list(interfaces.keys())[selected_interface_idx - 1]

# XDP (eBPF) program with configurable port number and network interface
xdp_program = f"""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int hello(struct __sk_buff *skb) {{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Check if packet has Ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    // Check if packet contains an IP header
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {{
        struct iphdr *ip = data + sizeof(struct ethhdr);

        // Check if it's a TCP packet and the destination port is {configurable_port}
        if (ip->protocol == IPPROTO_TCP) {{
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (tcp + 1 <= data_end && ntohs(tcp->dest) == {configurable_port}) {{
                // Drop the packet if the destination port matches {configurable_port}
                return XDP_DROP;
            }}
        }}
    }}

    // Pass the packet if it doesn't meet the drop condition
    return XDP_PASS;
}}
"""

# Load the XDP program with the configurable port number and network interface
bpf_program = xdp_program.replace('{configurable_port}', str(configurable_port))
bpf_program = bpf_program.replace('{configurable_interface}', selected_interface)
b = BPF(text=bpf_program)

# Attach the XDP program to the selected network interface
b.attach_xdp(interface=selected_interface, program=b.load_func("hello", BPF.XDP))

print(f"XDP program attached to {selected_interface} with port {configurable_port}. Press Ctrl+C to detach.")
try:
    b.trace_print()
except KeyboardInterrupt:
    pass

# Detach the XDP program from the network interface upon exit
b.remove_xdp(interface=selected_interface)
print(f"XDP program detached from {selected_interface}.")
