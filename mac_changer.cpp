#include <cstdlib>
#include <iostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <vector>
#include <algorithm>


std::string chosenInterface = "";
std::string newMACAdd = "";

void chooseInterface() {

    struct ifaddrs* interfaces = nullptr;
    struct ifaddrs* ifa = nullptr;

    if (getifaddrs(&interfaces) == -1) {
        std::cerr << "getifaddrs() failed.\n";
    }

    std::vector<std::string> interfaceNames;
    
    int index = 0;
    std::cout << "Available interfaces:\n";
    for (ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name != nullptr) {
            std::string name = ifa->ifa_name;
            if (std::find(interfaceNames.begin(), interfaceNames.end(), name) == interfaceNames.end()) {
                interfaceNames.push_back(name);
                std::cout << " [" << index << "] " << name << "\n";
                ++index;
            }
        }
    }

    if (interfaceNames.empty()) {
        
        std::cerr << "No interfaces found.\n";
        return;

    }

    int choice;
    std::cout << "Enter selection: ";
    std::cin >> choice;

    if (choice >= 0 && choice < interfaceNames.size()) {
        chosenInterface = interfaceNames[choice];
    } else {
        std::cerr << "Invalid choice.\n";
    }

    freeifaddrs(interfaces);

}

void chooseMACAddress() {

    std::string enteredMAC = "";
    

    std::cout << "Current MAC Address is ";
    std::cout << "Enter a new MAC address: ";
    std::cin >> enteredMAC;

    newMACAdd = enteredMAC;

}

void changeMAC(const std::string& i, const std::string& nM) {

    std::string lineOne = "ifconfig " + i + " down";
    const char* lineOne_cstr = lineOne.c_str();

    std::string lineTwo = "ifconfig " + i + " hw ether " + nM + "";
    const char* lineTwo_cstr = lineTwo.c_str();

    std::string lineThree = "ifconfig " + i + " up";
    const char* lineThree_cstr = lineThree.c_str();

    std::system(lineOne_cstr);
    std::system(lineTwo_cstr);
    std::system(lineThree_cstr);

}

int main() {

    chooseInterface();
    chooseMACAddress();
    changeMAC(chosenInterface, newMACAdd);
    
    return 0;
}
