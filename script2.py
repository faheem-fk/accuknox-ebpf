import os
import psutil
from bcc import BPF

# Get the process name and port number from user input
process_name = input("Enter the process name: ")
allowed_port = input("Enter the allowed port number (default is 4040): ")

# Use default port 4040 if user doesn't provide a port number
allowed_port = int(allowed_port) if allowed_port.isdigit() else 4040

# Check if the specified process exists
if process_name not in (p.info['name'] for p in psutil.process_iter(attrs=['name'])):
    print(f"Error: Process '{process_name}' not found.")
    exit()

# XDP (eBPF) program with configurable process name and allowed port number
xdp_program = f"""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_HASH(process_names, u32, char[TASK_COMM_LEN], 1024);  // Map to store process names by PID

SEC("xdp")
int allow_specific_port(struct __sk_buff *skb) {{
    // Get process name from skb (packet metadata)
    u32 pid = bpf_get_current_pid_tgid();
    char *process_name = process_names.lookup(&pid);
    if (process_name == 0) {{
        // Process name not found, drop the packet
        return XDP_DROP;
    }}

    int port = {allowed_port};  // Allowed port number

    // Check if packet has Ethernet header
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    // Check if packet contains an IP header
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {{
        struct iphdr *ip = data + sizeof(struct ethhdr);

        // Check if it's a TCP packet and the destination port is the allowed port
        if (ip->protocol == IPPROTO_TCP) {{
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (tcp + 1 <= data_end && ntohs(tcp->dest) == port) {{
                // Get process name from BPF map
                if (bpf_strcmp(process_name, "{process_name}") == 0) {{
                    // Allow the packet if the process name and port match
                    return XDP_PASS;
                }}
            }}
        }}
    }}

    // Drop the packet if it doesn't meet the allow condition
    return XDP_DROP;
}}
"""

# Load the XDP program with the configurable process name and allowed port number
bpf_program = xdp_program.replace('{process_name}', process_name)
bpf_program = bpf_program.replace('{allowed_port}', str(allowed_port))
b = BPF(text=bpf_program)

# Attach the eBPF program to the appropriate network interface
interface_name = input("Enter the network interface name: ")
b.attach_xdp(interface=interface_name, program=b.load_func("allow_specific_port", BPF.XDP))

print(f"XDP program attached to process '{process_name}' on port {allowed_port} for interface {interface_name}.")
try:
    b.trace_print()
except KeyboardInterrupt:
    pass

# Detach the XDP program from the network interface upon exit
b.remove_xdp(interface=interface_name)
print(f"XDP program detached from interface {interface_name}.")
