// === Sockets Training: Server That Accepts Client Connection and Data ===
// Sets up an IPv4 socket listening on Port 8080 (through any interface).
// Accepts client connection and data sent (up to 1KB).

#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {

    int serverSocketFileDescriptor;
    struct sockaddr_in serverAddress;

    // 1. Create socket:
    serverSocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);     // IPv4 domain, TCP type, TCP protocol
    if (serverSocketFileDescriptor == -1) {
        std::cerr << "Socket error: " << strerror(errno) << std::endl;
        return 1;
    }

    // 2. Bind socket to IP address and port:
    serverAddress.sin_family = AF_INET;                                         // IPv4
    serverAddress.sin_addr.s_addr = INADDR_ANY;                                 // Listen on all interfaces
    serverAddress.sin_port = htons(8080);                                       // Port 8080 - convert from host byte order to Network byte order (little endian to big endian)

    if (bind(serverSocketFileDescriptor, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Bind error: " << strerror(errno) << std::endl;
        close(serverSocketFileDescriptor);
        return 1;
    }

    // 3. Listen for incoming connections:
    if (listen(serverSocketFileDescriptor, 5) == -1) {
        std::cerr << "Listen error: " << strerror(errno) << std::endl;
        close(serverSocketFileDescriptor);
        return 1;
    }

    std::cout << "Server listening on port 8080...\n";

    while (true) {

        // Create a new socket for the incoming client connection:
        int clientSocketFileDescriptor;
        struct sockaddr_in clientAddress;
        socklen_t clientLen = sizeof(clientAddress);

        clientSocketFileDescriptor = accept(serverSocketFileDescriptor, (struct sockaddr*) &clientAddress, &clientLen);
        if (clientSocketFileDescriptor == -1) {
            std::cerr << "Accept error: " << strerror(errno) << std::endl;
            continue;                                                               // Try to accept another client
        }
        

        char clientIP[INET_ADDRSTRLEN];                                             // Buffer to hold IP string, the length of 16 for IPv4
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);   // Converts binary network IP to human-readable

        std::cout << "Client connected from " << clientIP << ":" << ntohs(clientAddress.sin_port) << std::endl;

        char clientMessage[1024];
        memset(clientMessage, 0, sizeof(clientMessage));

        // Receive data from client:
        int bytesReceived = recv(clientSocketFileDescriptor, clientMessage, sizeof(clientMessage) -1, 0);
        if (bytesReceived > 0) {
            std::cout << "Received " << bytesReceived << " bytes: " << clientMessage << std::endl;
        } else if (bytesReceived == 0) {
            std::cout << "Client disconnected without sending data.\n" << std::endl;
        } else {
            std::cerr << "Recv error: " << strerror(errno) << std::endl;            
        }

        close(clientSocketFileDescriptor);                                          // Close this client's socket
        std::cout << "Connection closed." << std::endl;

    }

    return 0;
}