#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <array>
#include <string>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>
#include <arpa/inet.h> // for inet_pton and inet_ntop
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <chrono>
#include <thread>


// *NETWORK SCANNER*
// WHAT THIS PROGRAM DOES:



////////// SECTION 1 ///////////////////////////////////////////////////////////
// Functions to attain local IP address, utilize the subnet mask to zero out the 
// last 8 bits of the IP address to obtain the subnet,
// i.e. 192.168.1.10 ---> 192.168.1.0
// In order to do this, the dotted IP string must be converted to uint32, have the
// net mask applied to it to zero out the last 8 bits, then convert the new subnet
// back into a dotted IP string to be used to generate the list of all IPs to send
// ARP requests to.

std::string getLocalIPv4Address() {
    std::string localIP;
    std::array<char, 256> buffer;
    
    FILE* pipe = popen("hostname -I", "r");
    if (pipe == nullptr) {
        std::cerr << "Failed to run command.\n";
        return "";
    }
    if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        localIP = buffer.data();
    }
    pclose(pipe);

    size_t space = localIP.find(" ");
    if (space != std::string::npos) {
        localIP = localIP.substr(0, space);
    }

    localIP.erase(localIP.find_last_not_of("\n") + 1);

    return localIP;

}

uint32_t convertIPtoINT(const std::string& ip_str) {
    struct in_addr ip_addr;
    inet_pton(AF_INET, ip_str.c_str(), &ip_addr);
    return ntohl(ip_addr.s_addr);
}

std::string convertINTtoIP(uint32_t ip_int) {
    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(ip_int);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

std::vector<std::string> generateIPsInSubnet(const std::string& baseIp) {
    std::vector<std::string> ipList;
    uint32_t base = convertIPtoINT(baseIp) & 0xFFFFFF00; // mask for /24

    for (uint32_t i = 1; i < 255; i++) {
        ipList.push_back(convertINTtoIP(base + i));
    }

    return ipList;
}
////////// END SECTION 1 ///////////////////////////////////////////////////////
////////// SECTION 2 ///////////////////////////////////////////////////////////
// This section will craft an ARP packet to be broadcasted.

int getInterfaceIndex(int socketDescriptor, const std::string& interfaceName) {
    struct ifreq interfaceReq;
    std::strncpy(interfaceReq.ifr_name, interfaceName.c_str(), IF_NAMESIZE);
    if (ioctl(socketDescriptor, SIOCGIFINDEX, &interfaceReq) == -1 ) {
        std::cerr << "ioctl SIOCGIFINDEX failed: " << strerror(errno) << "\n";
        return -1;
    }
    return interfaceReq.ifr_ifindex;
}

bool getInterfaceMAC(int socketDescriptor, const std::string& interfaceName, uint8_t* mac) {
    struct ifreq interfaceReq;
    std::strncpy(interfaceReq.ifr_name, interfaceName.c_str(), IF_NAMESIZE);
    if (ioctl(socketDescriptor, SIOCGIFHWADDR, &interfaceReq) == -1 ) {
        std::cerr << "ioctl SIOCGIFHWADDR failed: " << strerror(errno) << "\n";
        return false;
    }
    std::memcpy(mac, interfaceReq.ifr_hwaddr.sa_data, 6);
    return true;
}

void sendARPRequest(const std::string& interfaceName, const std::string& sourceIPstr, const std::string& targetIPstr) {
    
    int socketDescriptor = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    // Get interface index and MAC:
    int interfaceIndex = getInterfaceIndex(socketDescriptor, interfaceName);
    uint8_t sourceMAC[6];
    if (getInterfaceMAC(socketDescriptor, interfaceName, sourceMAC) == false) {
        close(socketDescriptor);
        std::cerr << "Socket closed.\n";
        return;
    }

    // Convert IP strings to bytes:
    uint8_t sourceIP[4], targetIP[4];
    inet_pton(AF_INET, sourceIPstr.c_str(), sourceIP);
    inet_pton(AF_INET, targetIPstr.c_str(), targetIP);

    // Build ARP request packet:
    unsigned char buffer[42];
    struct ether_header* ethHeaderPointer = (struct ether_header*) buffer;
    struct ether_arp* arpHeaderPointer    = (struct ether_arp*) (buffer + 14);

    // Ethernet header:
    memset(ethHeaderPointer->ether_dhost, 0xFF, 6);                          // Broadcast
    memcpy(ethHeaderPointer->ether_shost, sourceMAC, 6);                     // Source MAC
    ethHeaderPointer->ether_type = htons(ETHERTYPE_ARP);

    // ARP header:
    arpHeaderPointer->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);                   // Ethernet
    arpHeaderPointer->ea_hdr.ar_pro = htons(ETHERTYPE_IP);                   // IPv4
    arpHeaderPointer->ea_hdr.ar_hln = 6;
    arpHeaderPointer->ea_hdr.ar_pln = 4;
    arpHeaderPointer->ea_hdr.ar_op  = htons(ARPOP_REQUEST);

    memcpy(arpHeaderPointer->arp_sha, sourceMAC, 6);                         // Copy sender MAC to ARP packet
    memcpy(arpHeaderPointer->arp_spa, sourceIP, 4);                          // Copy sender IP to ARP packet
    memset(arpHeaderPointer->arp_tha, 0x00, 6);                              // Set target MAC to 0 because it is unknown
    memcpy(arpHeaderPointer->arp_tpa, targetIP, 4);                          // Copy target IP to ARP packet

    // Socket address:
    struct sockaddr_ll socketAddress{};
    socketAddress.sll_ifindex = interfaceIndex;
    socketAddress.sll_halen = ETH_ALEN;
    socketAddress.sll_family = AF_PACKET;
    memset(socketAddress.sll_addr, 0xFF, 6);                    // Broadcast

    if (sendto(socketDescriptor, buffer, 42, 0, (struct sockaddr*) &socketAddress, sizeof(socketAddress)) < 0) {
        std::cerr << "sendto failed: " << strerror(errno) << "\n";
    } else {
        std::cout << "ARP request sent to " << targetIPstr << "\n";
    }

    close(socketDescriptor);

}
////////// END SECTION 2 ///////////////////////////////////////////////////////
////////// SECTION 3 ///////////////////////////////////////////////////////////
// This section will listen for, capture and parse an ARP response.
void listenForARPReplies(const std::string& interfaceName, int timeoutMilliseconds = 3000) {
    
    // Open the network interface for packet capture:
    char errorBuffer[PCAP_ERRBUF_SIZE];     // holds errors from pcap
    pcap_t* pcapHandle = pcap_open_live(    
        interfaceName.c_str(),              // the interface (cstring)
        BUFSIZ,                             // the capture buffer size
        0,                                  // non-promiscuous mode
        timeoutMilliseconds, 
        errorBuffer);
    if (pcapHandle == nullptr) {
        std::cerr << "pcap_open_live failed: " << errorBuffer << "\n";
        return;
    }

    // Create and apply a filter to capture only ARP packets:
    struct bpf_program compiledFilterProgram;   
    const char* filterArgument = "arp";
    if (pcap_compile(pcapHandle, &compiledFilterProgram, filterArgument, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Failed to compile.\n";
        pcap_close(pcapHandle);
        return;
    }
    if (pcap_setfilter(pcapHandle, &compiledFilterProgram) == -1) {
        std::cerr << "Failed to apply ARP filter.\n";
        pcap_close(pcapHandle);
        return;
    }

    std::cout << "Listening for ARP replies...\n";

    const u_char* capturedPacket;
    struct pcap_pkthdr* packetHeader;
    int captureResult;

    while ((captureResult = pcap_next_ex(pcapHandle, &packetHeader, &capturedPacket)) >= 0) {
        if (captureResult == 0) {   // Timeout occurred, no packet.
            continue;               
        }
        // Skip the ethernet header (first 14 bytes), parse the ARP payload:
        struct ether_arp* arpPacket = (struct ether_arp*)(capturedPacket + 14);

        // Check if this is an ARP reply:
        if (ntohs(arpPacket->ea_hdr.ar_op) == ARPOP_REPLY) {
            char senderIPAddress[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arpPacket->arp_spa, senderIPAddress, sizeof(senderIPAddress));

            std::cout << "Reply from " << senderIPAddress << " - MAC: "
                << std::hex << std::setfill('0')
                << std::setw(2) << static_cast<unsigned int>(arpPacket->arp_sha[0]) << ":" // Without casting to unsigned int,
                << std::setw(2) << static_cast<unsigned int>(arpPacket->arp_sha[1]) << ":" // C++ is treating the MAC bytes as chars, 
                << std::setw(2) << static_cast<unsigned int>(arpPacket->arp_sha[2]) << ":" // resulting in garbage.
                << std::setw(2) << static_cast<unsigned int>(arpPacket->arp_sha[3]) << ":"
                << std::setw(2) << static_cast<unsigned int>(arpPacket->arp_sha[4]) << ":"
                << std::setw(2) << static_cast<unsigned int>(arpPacket->arp_sha[5]) << "\n";
        }
    }
    
    pcap_close(pcapHandle);

}
////////// END SECTION 3 ///////////////////////////////////////////////////////
////////// SECTION 4 ///////////////////////////////////////////////////////////
// Runs the ARP scan on all IPs in the subnet of the host machine.

void runARPScan(const std::string& interfaceName) {
    
    std::string localIP = getLocalIPv4Address();
    if (localIP.empty()) {
        std::cerr << "Failed to get local IP.\n";
        return;
    }

    std::vector<std::string> targets = generateIPsInSubnet(localIP);

    std::cout << "Sending ARP requests...\n";

    for (const std::string& ip : targets) {
        if (ip == localIP) {
            continue;           // skip local ip in ARP scan.
        }
        
        sendARPRequest(interfaceName, localIP, ip);

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::cout << "\nWaiting for responses...\n";
    listenForARPReplies(interfaceName);

}
////////// END SECTION 3 ///////////////////////////////////////////////////////


int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        std::cerr << "Example: " << argv[0] << " eth0\n";
        return 1;
    }

    std::string interfaceName = argv[1];

    runARPScan(interfaceName);    

    return 0;
}
