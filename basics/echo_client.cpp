// === TCP ECHO CLIENT ===
// This simple TCP client sends a message to a server on port 8080.
// It then receives the message echoed back from the server.

// Currently hardcoded for "127.0.0.1" localhost connections.

#include <arpa/inet.h>
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

class ClientSocket {
    private:
    int clientSocketFileDescriptor;

    public:
    ClientSocket(){};
    ~ClientSocket(){};

    void initialize() {
        clientSocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocketFileDescriptor == -1) {
            std::cerr << "[!] socket() initialization failed: " << strerror(errno) << std::endl;
            return;
        }
    }

    int getCSFD() {
        return clientSocketFileDescriptor;
    }

    void closeSocket() {
        std::cout << "Shutting down client socket..." << std::endl;
        close(clientSocketFileDescriptor);
        return;
    }
};

class Client {
    private:
    ClientSocket clientSocket;
    struct sockaddr_in serverSocketAddress;

    void setupServerSocketAddress() {
        serverSocketAddress.sin_family = AF_INET;
        serverSocketAddress.sin_port = htons(8080);

        if (inet_pton(AF_INET, "127.0.0.1", &serverSocketAddress.sin_addr) <= 0) {
            std::cerr << "[!] Invalid server IP address." << std::endl;
            clientSocket.closeSocket();
            return;
        }
    }

    void connectToServer() {
        if (connect(clientSocket.getCSFD(), (struct sockaddr*) &serverSocketAddress, sizeof(serverSocketAddress)) == -1) {
            std::cerr << "[!] connect() failure: " << strerror(errno) << std::endl;
            clientSocket.closeSocket();
        }
    }

    void sendMessageToServer() {
        const char* clientMessage = "Hello from client.";
        int bytesSent = send(clientSocket.getCSFD(), clientMessage, strlen(clientMessage), 0);
        if (bytesSent < 0) {
            std::cerr << "[!] send() failure: " << strerror(errno) << std::endl;
            clientSocket.closeSocket();
            return;
        }

        std::cout << "Sent " << bytesSent << " bytes to server." << std::endl;
    }

    void receiveMessageFromServer() {
        char serverMessage[1024];
        int bytesReceived = recv(clientSocket.getCSFD(), serverMessage, sizeof(serverMessage), 0);
        if (bytesReceived > 0) {
            serverMessage[bytesReceived] = '\0';     // Clean up garbage characters after message
            std::cout << "Received " << bytesReceived << " bytes: " << serverMessage << std::endl;
        } else if (bytesReceived == 0) {
            std::cout << "Server disconnected without replying with any data." << std::endl;
        } else {
            std::cerr << "[!] recv() failure: " << strerror(errno) << std::endl;
        }
    }
    
    public:
    Client(){};
    ~Client() {
        clientSocket.closeSocket();
    }

    void initialize() {
        clientSocket.initialize();
        setupServerSocketAddress();
        connectToServer();
        sendMessageToServer();
        receiveMessageFromServer();        
    }
};

int main() {

    Client client;
    client.initialize();

    return 0;
}
