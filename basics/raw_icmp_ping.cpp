// === Sockets Training: Raw Socket / Raw ICMP Packet Send and Receive ===
// This program sets up a raw socket, constructs a raw ICMP echo packet and sends to Google DNS.
// It listens for a response, and then parses and displays response.

#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

class ICMPPacket {
    private:
    std::array<char, 64> packet;
    const char* payload = "PingData123456";

    uint16_t calculateCheckSum(uint16_t* data, int length) {
        uint32_t sum = 0;                                                   
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

    public:
    ICMPPacket(){  
        memset(packet.data(), 0, sizeof(packet));
    };
    ~ICMPPacket(){};
    
    void craftPacket() {
        struct icmphdr* icmpHeaderSent = (struct icmphdr*) packet.data();
        icmpHeaderSent->type = ICMP_ECHO;
        icmpHeaderSent->code = 0;
        icmpHeaderSent->un.echo.id = getpid() & 0xFFFF;
        icmpHeaderSent->un.echo.sequence = 1;

        char* packetStart = &packet[0];
        char* payloadStart = packetStart + sizeof(struct icmphdr);
        memcpy(payloadStart, payload, strlen(payload));
        
        icmpHeaderSent->checksum = 0;
        icmpHeaderSent->checksum = calculateCheckSum((uint16_t*) packet.data(), sizeof(icmphdr) + strlen(payload));
    }

    std::array<char, 64> getPacket() {
        return packet;
    }
    const char* getPayload() {
        return payload;
    }
};

class DestinationSocket {
    private:
    ICMPPacket icmpPacket; 
    int destinationSocketFileDescriptor;
    struct sockaddr_in destinationAddress = {};
    struct sockaddr_in senderAddress = {};
    const char* destinationDNS = "8.8.8.8";
    std::array<char, 1024> receiveBuffer;

    void setupSocket() {
        destinationSocketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (destinationSocketFileDescriptor < 0) {
            std::cerr << "Destination socket() failure: " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }

        destinationAddress.sin_family = AF_INET;
        inet_pton(AF_INET, destinationDNS, &destinationAddress.sin_addr);
        return;
    }
    
    void sendPacket() {
        std::array<char, 64> rawPacket = icmpPacket.getPacket();
        if (sendto(destinationSocketFileDescriptor, 
            rawPacket.data(), sizeof(struct icmphdr) + strlen(icmpPacket.getPayload()), 0,
            (struct sockaddr*) &destinationAddress, sizeof(destinationAddress)) == -1) {
                std::cerr << "Raw packet sento() failure: " << strerror(errno) << std::endl;
                close(destinationSocketFileDescriptor);
                exit(EXIT_FAILURE);
        }

        std::cout << "ICMP echo request sent to " << destinationDNS << std::endl;
        return;
    }

    void captureICMPResponse() {
        socklen_t senderLength = sizeof(senderAddress);

        int bytesReceived = recvfrom(destinationSocketFileDescriptor, receiveBuffer.data(), sizeof(receiveBuffer), 0,
            (struct sockaddr*) &senderAddress, &senderLength);
        if (bytesReceived < 0) {
            std::cerr << "Capture ICMP response recvfrom() failure: " << strerror(errno) << std::endl;
            close(destinationSocketFileDescriptor);
            exit(EXIT_FAILURE);
        }

        std::cout << "Captured ICMP packet..." << std::endl;
    }
    
    void parseAndDisplayResponse() {
        struct iphdr* ipHeader = (struct iphdr*) receiveBuffer.data();
        int ipHeaderLength = ipHeader->ihl * 4; 

        struct icmphdr* icmpHeaderReceived;
        char* receivePtr = &receiveBuffer[0];
        icmpHeaderReceived = (struct icmphdr*)(receivePtr + ipHeaderLength);

        if (icmpHeaderReceived->type == ICMP_ECHOREPLY) {
            char senderIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &senderAddress.sin_addr, senderIP, sizeof(senderIP));
            std::cout << "Received ICMP echo reply from " << senderIP << " - seq="
                    << icmpHeaderReceived->un.echo.sequence << ", id=" << icmpHeaderReceived->un.echo.id << std::endl;
        } else {
            std::cout << "Received ICMP type " << (int)icmpHeaderReceived->type << ", code " << (int)icmpHeaderReceived->code << std::endl;
        }

        return;
    }

    public:
    DestinationSocket(){};
    ~DestinationSocket(){};

    void initialize() {
        setupSocket();
        icmpPacket.craftPacket();
        sendPacket();
        captureICMPResponse();
        parseAndDisplayResponse();
    }

    void closeSocket() {
        close(destinationSocketFileDescriptor);
        return;
    }
};

class ICMPPing {
    private:
    DestinationSocket destSocket;

    public:
    ICMPPing(){};
    ~ICMPPing(){
        destSocket.closeSocket();
    };

    void run() {
        destSocket.initialize();
    }
};


int main() {

    ICMPPing ping;
    ping.run();

    return 0;
}

