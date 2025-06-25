//=== PORT SCANNER ===
//
// TODO: Add stealth logic / arg
// TODO: Add ability to specify ports
// TODO: Add multithreaded banner grabbing as well

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <queue>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "port_scanner_port_lists.h"

struct ScanJob {
    public:
    std::string targetIP;
    int port;

    ScanJob(const std::string& ip_, int port_) {
        targetIP = ip_;
        port = port_;
    }
};
class ThreadPool {
    private:
    std::vector<std::thread> workerThreads;
    std::queue<std::function<void()>> tasks;

    std::mutex queueMutex;
    std::condition_variable condition;
    std::atomic<bool> stop;

    public:
    ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; ++i) {
            workerThreads.emplace_back([this]() {
                while(stop == false) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queueMutex);
                        this->condition.wait(lock, [this]() {
                            return this->stop || !this->tasks.empty();
                        });

                        if (this->stop == true && this->tasks.empty() == true) {
                            return;
                        }
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }

                    task();
                }
            });
        }
    }

    template<class F>
    void enqueue(F&& job) {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            tasks.emplace(std::forward<F>(job));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        stop = true;
        condition.notify_all();

        for (std::thread &worker : workerThreads) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    };
};

enum class PortScanMode {
    Top1000,
    Full
};
enum class PortStatus {
    OPEN,
    CLOSED
};

class Port {
    private:
    std::string bannerData;

    public:
    int portNum;
    PortStatus status;

    void setBannerData(const std::string& banner) {
        bannerData = banner;
    }

    std::string getBannerData() {
        return bannerData;
    }

};

class Target {
    private:
    std::vector<Port*> scannedPorts;

    public:
    std::string ip;

    void addPort(Port* p) {
        scannedPorts.push_back(p);
    }
    std::vector<Port*> getPorts() {
        return scannedPorts;
    }
};

class Scanner {
    private:
    ThreadPool* pool;
    std::mutex outputLock;
    std::mutex portLock;
    std::vector<Target*> targetIPs;
    std::vector<int> ports;


    void getPorts(PortScanMode mode, bool udp) {
        if (mode == PortScanMode::Top1000) {
            if (udp == true) {
                ports.assign(TOP_UDP_PORTS.begin(), TOP_UDP_PORTS.end());
                // DEBUG:
                std::cout << "UDP ports (top 1000) assigned for scanning." << std::endl;
            } else {
                ports.assign(TOP_TCP_PORTS.begin(), TOP_TCP_PORTS.end());
                // DEBUG:
                std::cout << "TCP ports (top 1000) assigned for scanning." << std::endl;
            }
        } else if (mode == PortScanMode::Full) {
            ports.reserve(65535);
            for (int i = 1; i <= 65535; ++i) {
                ports.push_back(i);
            }
            // DEBUG:
            std::cout << "All ports (65535) assigned for scanning." << std::endl;
        }
    }

    void runConnectionScan() {
        for (Target* &target : targetIPs) {
            std::cout << "Scanning " << target->ip << std::endl;

            for (int port : ports) {
                ScanJob job(target->ip, port);
                pool->enqueue([this, target, job]() {
                    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
                    if (socketFD < 0) {
                        return;
                    }

                    sockaddr_in addr {};
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(job.port);
                    inet_pton(AF_INET, target->ip.c_str(), &addr.sin_addr);

                    timeval timeout;
                    timeout.tv_sec = 2;
                    timeout.tv_usec = 0;
                    setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

                    int result = connect(socketFD, (sockaddr*)&addr, sizeof(addr));
                    close(socketFD);

                    Port* p = new Port;
                    p->portNum = job.port;

                    if (result == 0) {
                        p->status = PortStatus::OPEN;
                    } else {
                        p->status = PortStatus::CLOSED;
                    }

                    {
                        std::lock_guard<std::mutex> lock(outputLock);
                        std::cout << "  - Port " << p->portNum
                                << (result == 0 ? " is OPEN" : " is CLOSED") << std::endl;
                    }

                    std::lock_guard<std::mutex> lock(portLock);
                    target->addPort(p);
                });
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    void grabBanners() {
        for (Target* t : targetIPs) {
            for (Port* p : t->getPorts()) {
                if (p->status == PortStatus::CLOSED) {
                    continue;
                }

                int socketFD = socket(AF_INET, SOCK_STREAM, 0);
                if (socketFD < 0) {
                    continue;
                }

                sockaddr_in addr {};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(p->portNum);
                inet_pton(AF_INET, t->ip.c_str(), &addr.sin_addr);

                if (connect(socketFD, (sockaddr*)&addr, sizeof(addr)) < 0) {
                    close(socketFD);
                    continue;
                }

                timeval timeout {2, 0};
                setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

                std::array<char, 1024> buffer;
                memset(buffer.data(), 0, sizeof(buffer));
                int bytes = recv(socketFD, buffer.data(), sizeof(buffer) - 1, 0);

                if (bytes > 0) {
                    p->setBannerData(std::string(buffer.data()));
                    std::cout << "      [Banner] Port " << p->portNum << ":" << buffer.data() << std::endl;
                }

                close(socketFD);
            }
        }
    }
        
    public:
    PortScanMode scanMode = PortScanMode::Top1000;
    bool useTop1000 = false;
    bool useFullScan = false;
    bool isUDP = false;
    bool grabBanner = false;
    std::string outputFile;

    Scanner() {
        pool = new ThreadPool(50);
    }
    ~Scanner() {
        delete pool;
    }

    void addTargets(std::string ip_) {
        Target* t = new Target;
        t->ip = ip_;
        targetIPs.push_back(t);
    }

    std::vector<Target*> getTargets() {
        return targetIPs;
    }

    void run() {
        getPorts(scanMode, isUDP);
        runConnectionScan();

        if (grabBanner == true) {
            std::cout << "  Starting banner grabbing..." << std::endl;
            grabBanners();
        }

        if (outputFile.empty() != true) {
            std::ofstream outfile(outputFile);
            for (Target* t : targetIPs) {
                outfile << t->ip << ":" << std::endl;
                for (Port* p : t->getPorts()) {
                    outfile << "    Port " << p->portNum << ": ";
                    if (p->status == PortStatus::OPEN) {
                        outfile << "OPEN";
                    } else {
                        outfile << "CLOSED";
                    }
                    std::string banner = p->getBannerData();
                    if (banner.empty() != true) {
                        outfile << " | Banner: " << banner;
                    }
                    outfile << std::endl;
                }
                outfile << std::endl;
            }
            std::cout << "Results written to " << outputFile << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {    

    Scanner scanner;

    // Parse args:
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--targets-file") {
            if (i + 1 < argc) {
                std::ifstream infile(argv[++i]);
                std::string line;
                while (std::getline(infile, line)) {
                    if (line.empty() != true) {
                        scanner.addTargets(line);
                    }
                }
            } else {
                std::cerr << "Error: --targets-file requires a filename" << std::endl;
            }
        } else if (arg == "--top-1000") {
            scanner.useTop1000 = true;
            scanner.scanMode = PortScanMode::Top1000;
        } else if (arg == "--full") {
            scanner.useFullScan = true;
            scanner.scanMode = PortScanMode::Full;
        } else if (arg == "--UDP") {
            scanner.isUDP = true;
        } else if (arg == "--banner") {
            scanner.grabBanner = true;
        } else if (arg == "--output-file") {
            if (i + 1 < argc) {
                scanner.outputFile = argv[++i];
            } else {
                std::cerr << "Error: --output-file requires a filename" << std::endl;
            }
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: ./port_scanner [--targets-file targets.txt | target_ip] [--top-1000 | --full] [--UDP] [--banner] [--output-file file.txt]" << std::endl;
            return 0;
        } else if (arg[0] != '-') { // Assume it's a single target IP:            
            scanner.addTargets(arg);
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
    }

    // Other errors:
    if (scanner.getTargets().empty()) {
        std::cerr << "Error: no target specified" << std::endl;
        return 1;
    }
    if (scanner.useFullScan == true && scanner.useTop1000 == true) {
        std::cerr << "Error: must choose either --full or --top-1000, not both." << std::endl;
        return 1;
    }

    // Output recap:
    std::cout << "Targets:" << std::endl;
    for (const Target* t : scanner.getTargets()) {
        std::cout << "- " << t->ip << std::endl;
    }
    std::cout << "Scan mode: ";
    if (scanner.useFullScan == true) {
        std::cout << "Full port scan" << std::endl;
    } else {
        std::cout << "Top 1000 port scan" << std::endl;
    }
    if (scanner.isUDP == true) {
        std::cout << "UDP fallback enabled" << std::endl;
    }
    if (scanner.grabBanner == true) {
        std::cout << "Banner grabbing enabled" << std::endl;
    }
    if (scanner.outputFile.empty() != true) {
        std::cout << "Output file: " << scanner.outputFile << std::endl;
    }

    scanner.run();

    return 0;
}
