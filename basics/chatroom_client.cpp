//=== TCP CHATROOM CLIENT ===
// This is a simple TCP chatroom client that connects to the TCP chatroom server and
// receives messages sent from other connected clients.

// Currently hardcoded for "127.0.0.1" localhost connections.

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
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
            std::cerr << "[!] Client socket() failed to initialize: " << strerror(errno) << "." << std::endl;
            return;
        }
    }

    int getCSFD() {
        return clientSocketFileDescriptor;
    }

    void closeSocket() {
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
            std::cerr << "[!] connect() failure: " << strerror(errno) << "." << std::endl;
            clientSocket.closeSocket();
            return;
        }

        std::cout << "[*] Connected to chatroom. Type messages or /exit to quit." << std::endl;
    }

    void receiveMessagesFromServer() {
        char buffer[1024];
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytesReceived = recv(clientSocket.getCSFD(), buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) {
                std::cout << "[*] Disconnected from server." << std::endl;
                clientSocket.closeSocket();
                exit(0);
            }

            std::cout << buffer << std::flush << std::endl;
        }
    }

    void sendMessagesToServer() {
        std::thread receiver(&Client::receiveMessagesFromServer, this);
        receiver.detach();

        std::string input;
        while (true) {
            std::getline(std::cin, input);
            if (input == "/exit") {
                break;
            }
            send(clientSocket.getCSFD(), input.c_str(), input.length(), 0);
        }

        clientSocket.closeSocket();
        std::cout << "[*] Disconnected." << std::endl;
        return;
    }

    public:
    Client(){};
    ~Client(){
        clientSocket.closeSocket();
    }

    void initialize() {
        clientSocket.initialize();
        setupServerSocketAddress();
        connectToServer();
        sendMessagesToServer();
    }
};

int main() {

    Client client;
    client.initialize();

    return 0;
}
