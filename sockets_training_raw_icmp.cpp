// === Sockets Training: Raw Socket / Raw ICMP Packet Send and Receive ===
// Sets up a raw socket, constructs a raw ICMP echo packet and sends to Google DNS.
// Listens for a response. Parses response.

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

uint16_t calculateCheckSum(uint16_t* data, int length) {
    uint32_t sum = 0;                                                   // Start with 32-bit sum to handle possible overflow
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        sum += *((uint8_t*) data);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

int main() {

    int socketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketFileDescriptor < 0) {
        std::cerr << "Socket() error " << strerror(errno) << std::endl;
    }

    // Destination address setup:
    struct sockaddr_in destinationAddress{};
    destinationAddress.sin_family = AF_INET;                            
    const char* destinationDNS = "8.8.8.8";                                 // Google DNS
    inet_pton(AF_INET, destinationDNS, &destinationAddress.sin_addr);       // Presentation format to network byte format

    // Create ICMP packet (header + payload):
    char packet[64];
    memset(packet, 0, sizeof(packet));

    struct icmphdr* icmpHeaderSent = (struct icmphdr*) packet;
    icmpHeaderSent->type = ICMP_ECHO;
    icmpHeaderSent->code = 0;
    icmpHeaderSent->un.echo.id = getpid() & 0xFFFF;
    icmpHeaderSent->un.echo.sequence = 1;

    // Create payload:
    const char* payload = "PingData123456";
    memcpy(packet + sizeof(struct icmphdr), payload, strlen(payload));

    // Calculate checksum:
    icmpHeaderSent->checksum = 0;
    icmpHeaderSent->checksum = calculateCheckSum((uint16_t*) packet, sizeof(icmphdr) + strlen(payload));

    // Send packet:
    if (sendto(socketFileDescriptor, packet, sizeof(struct icmphdr) + strlen(payload), 0,
        (struct sockaddr*) &destinationAddress, sizeof(destinationAddress)) == -1) {
        std::cerr << "Sendto() error: " << strerror(errno) << std::endl;
        close(socketFileDescriptor);
        return 1;
    }

    std::cout << "ICMP Echo request sent to " << destinationDNS << std::endl;

    // Capture ICMP reply:
    char receiveBuffer[1024];
    struct sockaddr_in senderAddress{};
    socklen_t senderLength = sizeof(senderAddress);

    int bytesReceived = recvfrom(socketFileDescriptor, receiveBuffer, sizeof(receiveBuffer), 0, (struct sockaddr*) &senderAddress, &senderLength);
    if (bytesReceived < 0) {
        std::cerr << "Recvfrom() error: " << strerror(errno) << std::endl;
        close(socketFileDescriptor);
        return 1;
    }

    // Parse IP header:
    struct iphdr* ipHeader = (struct iphdr*) receiveBuffer;
    int ipHeaderLength = ipHeader->ihl * 4;                 // ihl = Internet Header Length; Packet = [ IP Header (20 bytes) ][ ICMP Header ][ Payload ]

    // Parse ICMP header (comes after IP header):
    struct icmphdr* icmpHeaderReceived = (struct icmphdr*)(receiveBuffer + ipHeaderLength);

    // Show results:
    if (icmpHeaderReceived->type == ICMP_ECHOREPLY) {
        char senderIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &senderAddress.sin_addr, senderIP, sizeof(senderIP));
        std::cout << "Received ICMP echo reply from " << senderIP << " - seq="
        << icmpHeaderReceived->un.echo.sequence << ", id=" << icmpHeaderReceived->un.echo.id << std::endl;
    } else {
        std::cout << "Received ICMP type " << (int)icmpHeaderReceived->type << ", code " << (int)icmpHeaderReceived->code << std::endl;
    }

    close(socketFileDescriptor);

    return 0;
}

