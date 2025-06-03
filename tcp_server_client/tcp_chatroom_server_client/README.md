# TCP Multi-client Chatroom (C++)

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
