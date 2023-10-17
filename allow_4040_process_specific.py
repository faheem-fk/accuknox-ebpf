from bcc import BPF
import psutil

# Get the process name and port number from user input
process_name = input("Enter the process name: ")
allowed_port = int(input("Enter the allowed port number: "))

# XDP (eBPF) program with configurable process name and allowed port number
xdp_program = f"""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int allow_specific_port(struct __sk_buff *skb) {{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Get process name from skb (packet metadata)
    char process_name[] = "{process_name}";
    int port = {allowed_port};

    // Check if packet has Ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    // Check if packet contains an IP header
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {{
        struct iphdr *ip = data + sizeof(struct ethhdr);

        // Check if it's a TCP packet and the destination port is the allowed port
        if (ip->protocol == IPPROTO_TCP) {{
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (tcp + 1 <= data_end && ntohs(tcp->dest) == port) {{
                // Check process name
                struct task_struct *task = (struct task_struct *)bpf_get_current_task();
                char comm[TASK_COMM_LEN];
                bpf_get_current_comm(&comm, sizeof(comm));
                if (bpf_strcmp(comm, process_name) == 0) {{
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

# Attach the XDP program to the appropriate network interface
interfaces = psutil.net_if_addrs()
print("Available Network Interfaces:")
for idx, interface in enumerate(interfaces.keys(), start=1):
    print(f"{idx}: {interface}")

selected_interface_idx = int(input("Enter the number corresponding to the network interface: "))
selected_interface = list(interfaces.keys())[selected_interface_idx - 1]

b.attach_xdp(interface=selected_interface, program=b.load_func("allow_specific_port", BPF.XDP))

print(f"XDP program attached to {selected_interface} for process '{process_name}' on port {allowed_port}. Press Ctrl+C to detach.")
try:
    b.trace_print()
except KeyboardInterrupt:
    pass

# Detach the XDP program from the network interface upon exit
b.remove_xdp(interface=selected_interface)
print(f"XDP program detached from {selected_interface}.")
