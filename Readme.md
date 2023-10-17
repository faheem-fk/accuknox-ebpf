# Network Traffic Control with eBPF Scripts

Welcome to our network traffic control tool powered by eBPF! 🚀 This program allows you to effortlessly manage network traffic on your Linux system using two simple Python scripts.

## What These Scripts Do

1. **Drop TCP Packets on a Specific Port:** Use this script if you need to block traffic on a particular port.
2. **Allow Traffic for a Specific Process and Port:** This script ensures that only a specific process can communicate through a chosen port, blocking other traffic for that process.

## Requirements

Before getting started, make sure you have the following:

- **Python 3.11.2**
- **Packages:** `bcc`, `psutil`

You can install the required packages using the following command:

```bash
pip install --use-pep517 bcc psutil
```

## Tested Environment

These scripts have been tested and validated on a Debian Bookworm Linux system, using Python version 3.11.2. While they have been specifically tested on this configuration, they might also work on other Linux distributions.

## Running the Scripts

1. **Clone the Repository:**
   ```bash
   git clone git@github.com:faheem-fk/accuknox-ebpf.git
   cd accuknox-ebpf
   ```

2. **Configuration:**
   - Edit `script1.py` to specify the port number you want to block.
   - Customize `script2.py` with the desired process name, allowed port, and network interface.

3. **Run the Scripts:**
   - To drop packets on a specific port:
     ```bash
     python script1.py
     ```
   - To allow traffic for a specific process and port:
     ```bash
     python script2.py
     ```

4. **Follow On-Screen Instructions:**
   - The scripts will prompt you for necessary details such as the port number, process name, and network interface.

5. **Monitoring:**
   - Observe the terminal for any relevant messages. The scripts will manage network traffic according to your configurations.
