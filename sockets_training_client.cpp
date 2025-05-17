// === Sockets Training: Client That Connects to Server and Sends Data ===
// Sets up an IPv4 socket on Port 8080.
// Sends a message over TCP connection.

#include <stdio.h>
#include <iostream>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {

    int clientSocketFileDescriptor;
    clientSocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);             // IPv4 domain, TCP type, TCP protocol
    if (clientSocketFileDescriptor == -1) {
        std::cerr << "Socket error: " << strerror(errno) << std::endl;
        return 1;
    }


    struct sockaddr_in serverSocketAddress;                          // Client does not create a socket for server, merely an address to what will be the server's receiving end socket
    serverSocketAddress.sin_family = AF_INET;                                           // IPv4
    serverSocketAddress.sin_port = htons(8080);                                         // Port 8080 - convert from host byte order to Network byte order (little endian to big endian)

    // Convert IP string to binary form:
    if (inet_pton(AF_INET, "127.0.0.1", &serverSocketAddress.sin_addr) <= 0) {
        std::cerr << "Invalid address" << std::endl;
        close(clientSocketFileDescriptor);
        return 1;
    }

    // Connect to server:
    if (connect(clientSocketFileDescriptor, (struct sockaddr*) &serverSocketAddress, sizeof(serverSocketAddress)) == -1) {
        std::cerr << "Connect error: " << strerror(errno) << std::endl;
        close(clientSocketFileDescriptor);
        return 1;
    }

    // Send message to server:
    const char* clientMessage = "Hello from client.";
    int bytesSent = send(clientSocketFileDescriptor, clientMessage, strlen(clientMessage), 0);
    if (bytesSent == -1) {
        std::cerr << "Send error: " << strerror(errno) << std::endl;
        close(clientSocketFileDescriptor);
        return 1;
    }

    std::cout << "Sent " << bytesSent << " bytes to server." << std::endl;

    close(clientSocketFileDescriptor);
    return 0;

}