//=== FILE TRANSFER CLIENT ===
// This client reads a file from disk, extracts it, connects to server,
// and then sends file to the server.

// Currently hardcoded for "127.0.0.1" localhost connections.

#include <algorithm>
#include <arpa/inet.h>
#include <iostream>
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

    int getCSFD() {
        return clientSocketFileDescriptor;
    }

    void initialize() {
        clientSocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocketFileDescriptor == -1) {
            std::cerr << "[!] ClientSocket socket() error: " << strerror(errno) << std::endl;
            return;
        }
    }

    void closeClientSocket() {
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

        if (inet_pton(AF_INET, "127.0.0.1", &serverSocketAddress.sin_addr.s_addr) <= 0) {
            std::cerr << "[!] Invalid server IP address." << std::endl;
            clientSocket.closeClientSocket();
        }
        return;
    }

    void connectToServer() {
        if (connect(clientSocket.getCSFD(), (struct sockaddr*) &serverSocketAddress, sizeof(serverSocketAddress)) == -1) {
            std::cerr << "ClientSocket connect() failed: " << strerror(errno) << std::endl;
            clientSocket.closeClientSocket();
            return;
        }

        std::cout << "Connected to server." << std::endl;
        return;
    }

    void sendFilesToServer() {
        std::string filePath;
        std::string filename;

        std::cout << "Enter file path to send: ";
        std::getline(std::cin >> std::ws, filePath);
        size_t lastSlash = filePath.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            filename = filePath.substr(lastSlash + 1);
        } else {
            filename = filePath;   
        }

        FILE* inputFile = fopen(filePath.c_str(), "rb");
        if (inputFile == nullptr) {
            std::cerr << "[!] Could not open file: " << filePath << std::endl;
            return;
        }

        // Get file size:
        fseek(inputFile, 0, SEEK_END);
        uint64_t fileSize = ftell(inputFile);
        rewind(inputFile);

        std::cout << "Sending file: " << filename << " (" << fileSize << " bytes)" << std::endl;

        uint32_t filenameLength = htonl(static_cast<uint32_t>(filename.length()));        
        if (send(clientSocket.getCSFD(), &filenameLength, sizeof(filenameLength), 0) == -1) {
            std::cerr << "[!] Failed to send filename length." << std::endl;
            fclose(inputFile);
            return;
        }
        if (send(clientSocket.getCSFD(), filename.c_str(), filename.length(), 0) == -1) {
            std::cerr << "[!] Failed to send filename." << std::endl;
            return;
        }
        uint64_t fileSizeNet = htobe64(fileSize);
        if (send(clientSocket.getCSFD(), &fileSizeNet, sizeof(fileSizeNet), 0) == -1) {
            std::cerr << "[!] Failed to send file size." << std::endl;
            return;
        }

        char fileBuffer[4096];
        size_t bytesRead;
        while ((bytesRead = fread(fileBuffer, sizeof(char), sizeof(fileBuffer), inputFile)) > 0) {
            if (send(clientSocket.getCSFD(), fileBuffer, bytesRead, 0) == -1) {
                std::cerr << "[!] Failed while sending file content." << std::endl;
                break;
            }
        }

        fclose(inputFile);
        std::cout << "File sent successfully." << std::endl;
    }

    public:
    Client(){};
    ~Client(){
        clientSocket.closeClientSocket();
    };

    void initialize() {
        clientSocket.initialize();
        setupServerSocketAddress();
        connectToServer();
        sendFilesToServer();
    }

};

int main() {

    Client client;
    client.initialize();

    return 0;
}
