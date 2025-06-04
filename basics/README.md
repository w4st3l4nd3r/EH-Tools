
# Basics / Training

This repository contains simple TCP server/client programs.

### 1. TCP Echo Server/Client (C++)
`echo_server.cpp` `echo_client.cpp`

A command-line tool that:
- Runs a server that accepts localhost client socket connection;
- Receives messages from client, then echoes the message back to the client.

**Key Learning:**
- More socket creation utilizing `socket()`, `connect()`, `accept()`, `listen()`, `send()`, `recv()` etc.

**Usage:**
```bash
g++ tcp_server.cpp -o tcp_server
g++ tcp_client.cpp -o tcp_client
sudo ./tcp_server
sudo ./tcp_client
```

![echo_server_client_screenshot](echo_server_client_example.jpg)

### 2. TCP Multi-client Chatroom (C++)
`chatroom_server.cpp` `chatroom_client.cpp`

A command-line based TCP chatroom that:
- Utilizes muilt-threading to accept multiple concurrent clients;
- Broadcasts all messages sent by clients to all other clients;
- Allows graceful client exit with `/exit`;
- Allows administrator commands to `/kick` a client or `/list` list all connected clients.

**Key Learning:**
- Multi-threading (`std::thread`) and thread safety (`std::mutex` / `std::lock_guard`);
- More work with socket creation and management.

**Usage:**
```bash
g++ -pthread tcp_chatroom_server.cpp -o chatroom_server
g++ -pthread tcp_chatroom_client.cpp -o chatroom_client
./chatroom_server
./chatroom_client
```

