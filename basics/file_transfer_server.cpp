//=== FILE TRANSFER SERVER ===
// This program runs a server to accept file transfers from connected clients,
// then writes them to the local disk.

#include <algorithm>
#include <arpa/inet.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

class ServerSocket {
    private:
    int serverSocketFileDescriptor;
    struct sockaddr_in serverSocketAddress;
    socklen_t serverSize = sizeof(serverSocketAddress);

    public:
    ServerSocket(){};
    ~ServerSocket(){};

    int getSSFD() {
        return serverSocketFileDescriptor;
    }

    bool initialize() {
        serverSocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocketFileDescriptor == -1) {
            std::cerr << "[!] ServerSocket socket() failed: " << strerror(errno) << std::endl;
            return false;
        }

        serverSocketAddress.sin_family = AF_INET;
        serverSocketAddress.sin_addr.s_addr = INADDR_ANY;
        serverSocketAddress.sin_port = htons(8080);

        if (bind(serverSocketFileDescriptor, (struct sockaddr*) &serverSocketAddress, serverSize) == -1) {
            std::cerr << "[!] ServerSocket bind() failed: " << strerror(errno) << std::endl;
            return false;
        }        

        return true;
    }

    void closeServerSocket() {
        std::cout << "Closing server socket..." << std::endl;
        close(serverSocketFileDescriptor);
        return;
    }

};

class ClientSocket {
    private:
    int clientSocketFileDescriptor;
    struct sockaddr_in clientSocketAddress;
    socklen_t clientSize = sizeof(clientSocketAddress);

    public:
    ClientSocket(){};
    ~ClientSocket(){};

    int getCSFD() {
        return clientSocketFileDescriptor;
    }

    void initialize(int serverSocketFD) {
        clientSocketFileDescriptor = accept(serverSocketFD, (struct sockaddr*) &clientSocketAddress, &clientSize);
        if (clientSocketFileDescriptor == -1) {
            std::cerr << "[!] ClientSocket accept() failed: " << strerror(errno) << std::endl;
            closeClientSocket();
            return;
        }
    }

    void closeClientSocket() {
        std::cout << "Closing client socket..." << std::endl;
        close(clientSocketFileDescriptor);
        return;
    }
};

class Server {
    private:
    ServerSocket serverSocket;
    ClientSocket clientSocket;

    void createServerSocket() {
        if(serverSocket.initialize() == false) {
            std::cerr << "Failed to initialize server socket." << std::endl;
            exit(EXIT_FAILURE);
        }
        return;
    }
    void createClientSocket() {
        clientSocket.initialize(serverSocket.getSSFD());
        return;
    }
    void listenForClients() {
        if (listen(serverSocket.getSSFD(), 5) == -1) {
            std::cerr << "[!] Server listen() failed: " << strerror(errno) << std::endl;
            serverSocket.closeServerSocket();
            return;
        }

        std::cout << "Server listening on port 8080..." << std::endl;
    }
    void receiveFilesFromClient() {

        uint32_t filenameLength = 0;
        char filenameBuffer[1024] = {0};
        uint64_t fileSize = 0;
        char fileBuffer[4096];

        if (recv(clientSocket.getCSFD(), &filenameLength, sizeof(filenameLength), 0) <= 0) {
            std::cerr << "[!] Server failed to receive filename length from client." << std::endl;
            return;
        }
        filenameLength = ntohl(filenameLength);

        if (recv(clientSocket.getCSFD(), filenameBuffer, filenameLength, 0) <= 0) {
            std::cerr << "[!] Server failed to receive filename from client." << std::endl;
            return;
        }
        std::string filename(filenameBuffer, filenameLength);
        
        if (recv(clientSocket.getCSFD(), &fileSize, sizeof(fileSize), 0) <= 0) {
            std::cerr << "[!] Server failed to receive file size from client." << std::endl;
            return;
        }
        fileSize = be64toh(fileSize);

        std::cout << "Receiving file: " << filename << " (" << fileSize << " bytes)" << std::endl;

        FILE* outputFile = fopen(filename.c_str(), "wb");
        if (outputFile == nullptr) {
            std::cerr << "[!] Could not open file to write." << std::endl;
            return;
        }
        
        uint64_t totalReceived = 0;
        while (totalReceived < fileSize) {
            ssize_t bytesReceived = recv(clientSocket.getCSFD(), fileBuffer, sizeof(fileBuffer), 0);
            if (bytesReceived <= 0) {
                std::cerr << "[!] Error receiving file content." << std::endl;
                break;
            }

            fwrite(fileBuffer, sizeof(char), bytesReceived, outputFile);
            totalReceived += bytesReceived;
        }

        fclose(outputFile);

        std::cout << "File received and saved successfully." << std::endl;        
    }

    public:
    Server(){};
    ~Server(){
        serverSocket.closeServerSocket();
        clientSocket.closeClientSocket();
    };

    void run() {
        createServerSocket();
        listenForClients();
        createClientSocket();
        receiveFilesFromClient();
    }

};

int main() {

    Server server;
    server.run();

    return 0;
}
