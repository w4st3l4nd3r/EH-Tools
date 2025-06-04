### 1. ARP-Based Network Scanner
`arp_scanner.cpp`

A command-line tool that scans local `/24` subnet for active hosts by:
- Generating raw ARP request packets using raw sockets;
- Sending requests to each IP in local subnet;
- Capturing ARP replies using `libpcap`;
- Displaying IP, MAC and Vendor of responding devices.

**Key Learning:**
- Building raw Ethernet + ARP packets;
- Using `ioctl()` and `AF_PACKET` sockets;
- Applying BPF filters with `libpcap`;
- Using a .json file for vendor data;
- Understanding subnetting and IP manipulation at the byte level.

**Usage:**
```bash
g++ network_scanner.cpp -o network_scanner -lpcap
sudo ./network_scanner eth0
```

![arp_scanner_screenshot](arp_scanner_example.jpg)
