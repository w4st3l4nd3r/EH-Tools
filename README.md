# Ethical Hacking Tools (C++)

This repository contains networking tools written in modern C++ as part of my path to learning programming and ethical hacking.

## Tools Included
### 1. `mac_changer.cpp` — MAC Address Changer
A command-line tool that allows the user to:
- View a list of available network interfaces;
- Select an interface from the list;
- View current MAC address;
- Designate a new MAC address for the selected interface.

**Key Learning:**
- Parsing shell command output;
- Using `popen()/pclose()`, `fgets()` and `regex` to process interface data;

**Usage:**
```bash
g++ mac_changer.cpp -o mac_changer
sudo ./mac_changer
```

### 2. `network_scanner.cpp` — ARP-Based Network Scanner
