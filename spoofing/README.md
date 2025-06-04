### 1. MAC Address Changer
`mac_changer.cpp`

A command-line tool that allows the user to:
- View a list of available network interfaces;
- Select an interface from the list;
- View current MAC address;
- Designate a new MAC address for the selected interface.

**Key Learning:**
- Parsing shell command output;
- Using `popen()`/`pclose()`, `fgets()` and `regex` to process interface data.

**Usage:**
```bash
g++ mac_changer.cpp -o mac_changer
sudo ./mac_changer
```

![mac_changer_creenshot](mac_changer_example.jpg)
