// === MAC Address Changer ===
// Allows user to select from available interfaces, then changes the MAC address
// according to what the user defines.

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <regex>
#include <vector>

#ifdef _WIN32
    #define popen _popen
    #define pclose _pclose
#endif

// === SECTION 1: Choose Interface ===
// Retreives list of local interfaces and lets the user choose from them.
std::string chosenInterface = "";
void chooseInterface() {

    std::vector<std::string> interfaceNames;
    std::array<char, 256> buffer;
    
    FILE* pipe = popen("ip -o link show", "r");
    if (pipe == nullptr) {
        std::cerr << "Failed to run ip command.\n";
        return;
    }
    std::cout << "Available interfaces:\n";    
    int index = 0;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        std::string line = buffer.data();

        std::smatch match;
        std::regex interfaceRegex(R"(\d+: (\w+):)");
        if (std::regex_search(line, match, interfaceRegex)) {
            std::string name = match[1];
            interfaceNames.push_back(name);
            std::cout << " [" << index << "] " << name << "\n";
            index++;
        }
    }
    pclose(pipe);

    if (interfaceNames.empty()) {        
        std::cerr << "No interfaces found.\n";
        return;
    }

    int choice;
    bool validChoice = false;
    while (validChoice == false) {
        std::cout << "Enter selection: ";
        std::cin >> choice;

        if (choice >= 0 && choice < interfaceNames.size()) {
            chosenInterface = interfaceNames[choice];
            validChoice = true;
        } else {
            std::cerr << "Invalid choice.\n";
        }
    }    

}

// === SECTION 2: Retreive & Display Current MAC ===
std::string getMACAddress(const std::string& iface) {

    std::array<char, 256> buffer;
    std::string result;

    std::string cmd = "ip link show " + iface;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe == nullptr) {
        std::cerr << "Failed to run command.\n";
        return "";
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);

    std::regex MACregex("link/ether ([[:xdigit:]]{2}(:[[:xdigit:]]{2}){5})");
    std::smatch match;
    if (std::regex_search(result, match, MACregex)) {
        return match.str(0);
    }

    return ""; // No match found.

}
void displayMACAddress() {

    std::string currentMAC = getMACAddress(chosenInterface);
    if(!currentMAC.empty()) {
        std::cout << "Current MAC address: " + getMACAddress(chosenInterface) + "\n";
    } else {
        std::cerr << "Could not retrieve MAC address for interface " << chosenInterface << "\n";
    }    

}

// === SECTION 3: User Input For New MAC Address ===
std::string newMACAddr = "";
void chooseMACAddress(std::string& nM) {
    
    std::cout << "Enter a new MAC address: ";
    std::cin >> nM;

}
void changeMAC(const std::string& interf, const std::string& nM) {    

    std::vector<std::string> commands = {
        "ip link set dev " + interf + " down", 
        "ip link set dev " + interf + " address " + nM, 
        "ip link set dev " + interf + " up"};

    for (int x = 0; x < commands.size(); x++) {
        std::system(commands[x].c_str());
    }

}

// === SECTION 4: Program Entry ===
int main() {

    chooseInterface();
    displayMACAddress();
    chooseMACAddress(newMACAddr);
    changeMAC(chosenInterface, newMACAddr);
    displayMACAddress();
    
    return 0;
}
