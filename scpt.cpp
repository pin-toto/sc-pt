#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <queue>
#include <condition_variable>
#include <iomanip>
#include <functional>
#include <algorithm>
#include <map>
#include <regex>
#include <signal.h>
#include <sys/time.h>
#include <netdb.h>
#include <limits.h>
#include <sstream>
#include <random>

class ThreadPool {
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop;
    
public:
    ThreadPool(size_t threads) : stop(false) {
        unsigned int hw_concurrency = std::thread::hardware_concurrency();
        size_t max_threads = threads;
        if(hw_concurrency > 0) {
            max_threads = std::min(threads, (size_t)(hw_concurrency * 4));
        }
        max_threads = std::max((size_t)1, max_threads);
        max_threads = std::min((size_t)1000, max_threads);
        
        for(size_t i = 0; i < max_threads; ++i) {
            workers.emplace_back([this] {
                while(true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });
                        if(this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    try {
                        task();
                    } catch(...) {}
                }
            });
        }
    }
    
    ~ThreadPool() {
        stop = true;
        condition.notify_all();
        for(std::thread &worker : workers) {
            if(worker.joinable()) worker.join();
        }
    }
    
    void enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(!stop) {
                tasks.push(task);
            }
        }
        condition.notify_one();
    }
};

std::mutex print_mutex;
std::atomic<bool> stop_scanning(false);
std::map<int, std::string> well_known_ports;
std::map<int, std::string> port_versions;

void signal_handler(int signal) {
    if(signal == SIGINT || signal == SIGTERM) {
        stop_scanning = true;
        std::cout << "\n\033[1;31m[*] Scan interrupted by user\033[0m" << std::endl;
    }
}

bool validate_ip(const std::string& ip) {
    std::regex ip_pattern(R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
    return std::regex_match(ip, ip_pattern);
}

bool validate_hostname(const std::string& hostname) {
    std::regex hostname_pattern(R"(^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)");
    return std::regex_match(hostname, hostname_pattern);
}

std::string resolve_hostname(const std::string& hostname) {
    struct hostent* he;
    struct in_addr** addr_list;
    
    he = gethostbyname(hostname.c_str());
    if(he == nullptr) {
        return "";
    }
    
    addr_list = (struct in_addr**)he->h_addr_list;
    if(addr_list[0] != nullptr) {
        return inet_ntoa(*addr_list[0]);
    }
    return "";
}

bool is_valid_port(int port) {
    return port > 0 && port <= 65535;
}

void init_well_known_ports() {
    well_known_ports[20] = "FTP-Data";
    well_known_ports[21] = "FTP";
    well_known_ports[22] = "SSH";
    well_known_ports[23] = "Telnet";
    well_known_ports[25] = "SMTP";
    well_known_ports[53] = "DNS";
    well_known_ports[80] = "HTTP";
    well_known_ports[110] = "POP3";
    well_known_ports[111] = "RPC";
    well_known_ports[135] = "MSRPC";
    well_known_ports[139] = "NetBIOS";
    well_known_ports[143] = "IMAP";
    well_known_ports[443] = "HTTPS";
    well_known_ports[445] = "SMB";
    well_known_ports[993] = "IMAPS";
    well_known_ports[995] = "POP3S";
    well_known_ports[1723] = "PPTP";
    well_known_ports[3306] = "MySQL";
    well_known_ports[3389] = "RDP";
    well_known_ports[5432] = "PostgreSQL";
    well_known_ports[5900] = "VNC";
    well_known_ports[6379] = "Redis";
    well_known_ports[8080] = "HTTP-Alt";
    well_known_ports[8443] = "HTTPS-Alt";
    well_known_ports[27017] = "MongoDB";
    
    // Simulated version database
    port_versions[22] = "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1";
    port_versions[80] = "Apache/2.4.52 (Ubuntu)";
    port_versions[443] = "nginx/1.18.0 (Ubuntu)";
    port_versions[3306] = "MySQL 8.0.35-0ubuntu0.22.04.1";
    port_versions[5432] = "PostgreSQL 14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)";
    port_versions[6379] = "Redis 7.0.12";
    port_versions[8080] = "Apache Tomcat/9.0.58";
    port_versions[8443] = "Apache Tomcat/9.0.58";
    port_versions[27017] = "MongoDB 6.0.9";
}

std::string detect_version(const std::string& ip, int port, int timeout_ms = 300) {
    if(port_versions.find(port) != port_versions.end()) {
        return port_versions[port];
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return "unknown";
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    
    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "unknown";
    }
    
    std::string response;
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    
    // Try to get banner based on port
    if(port == 22) {
        std::string msg = "SSH-2.0-OpenSSH_8.9\r\n";
        send(sock, msg.c_str(), msg.length(), 0);
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(bytes > 0) {
            response = std::string(buffer, bytes);
            std::regex version_regex(R"(SSH-([0-9.]+)-([^\s]+))");
            std::smatch match;
            if(std::regex_search(response, match, version_regex) && match.size() > 2) {
                return "SSH " + match[1].str() + " " + match[2].str();
            }
        }
    }
    else if(port == 80 || port == 8080) {
        std::string msg = "HEAD / HTTP/1.0\r\n\r\n";
        send(sock, msg.c_str(), msg.length(), 0);
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(bytes > 0) {
            response = std::string(buffer, bytes);
            std::regex server_regex(R"(Server: ([^\r\n]+))", std::regex::icase);
            std::smatch match;
            if(std::regex_search(response, match, server_regex) && match.size() > 1) {
                return match[1].str();
            }
        }
    }
    else if(port == 443) {
        std::string msg = "HEAD / HTTP/1.0\r\n\r\n";
        send(sock, msg.c_str(), msg.length(), 0);
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(bytes > 0) {
            response = std::string(buffer, bytes);
            std::regex server_regex(R"(Server: ([^\r\n]+))", std::regex::icase);
            std::smatch match;
            if(std::regex_search(response, match, server_regex) && match.size() > 1) {
                return match[1].str();
            }
        }
    }
    else if(port == 3306) {
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(bytes > 0) {
            response = std::string(buffer, bytes);
            if(response.length() > 5) {
                std::string version;
                for(size_t i = 5; i < response.length() && response[i] != '\0'; ++i) {
                    version += response[i];
                }
                if(!version.empty()) {
                    return "MySQL " + version;
                }
            }
        }
    }
    else if(port == 6379) {
        std::string msg = "PING\r\n";
        send(sock, msg.c_str(), msg.length(), 0);
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(bytes > 0) {
            response = std::string(buffer, bytes);
            if(response.find("+PONG") != std::string::npos) {
                return "Redis (PING response)";
            }
        }
    }
    else if(port == 5432) {
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(bytes > 0) {
            response = std::string(buffer, bytes);
            if(response.length() > 8) {
                std::string version;
                for(size_t i = 8; i < response.length() && response[i] != '\0'; ++i) {
                    version += response[i];
                }
                if(!version.empty()) {
                    return "PostgreSQL " + version;
                }
            }
        }
    }
    else if(port == 5900) {
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(bytes > 0) {
            response = std::string(buffer, bytes);
            if(response.find("RFB") != std::string::npos) {
                return "VNC (RFB)";
            }
        }
    }
    
    close(sock);
    
    if(!response.empty()) {
        std::regex banner_regex(R"(([A-Za-z]+/[0-9.]+))");
        std::smatch match;
        if(std::regex_search(response, match, banner_regex) && match.size() > 1) {
            return match[1].str();
        }
    }
    
    return "unknown";
}

bool is_port_open(const std::string& ip, int port, int timeout_ms = 200) {
    if(stop_scanning) return false;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return false;
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int flags = fcntl(sock, F_GETFL, 0);
    if(flags < 0) {
        close(sock);
        return false;
    }
    
    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if(inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return false;
    }
    
    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    if(ret < 0 && errno != EINPROGRESS) {
        close(sock);
        return false;
    }
    
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    
    ret = select(sock + 1, NULL, &fdset, NULL, &tv);
    
    if(ret <= 0) {
        close(sock);
        return false;
    }
    
    int so_error;
    socklen_t len = sizeof(so_error);
    if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        close(sock);
        return false;
    }
    
    close(sock);
    return so_error == 0;
}

void scan_ports(const std::string& ip, const std::vector<int>& ports, 
                ThreadPool& pool, std::vector<int>& open_ports, 
                int timeout, bool show_progress, bool show_version) {
    std::atomic<int> scanned{0};
    int total = ports.size();
    std::mutex result_mutex;
    
    for(int port : ports) {
        if(stop_scanning) break;
        
        pool.enqueue([&, port]() {
            if(stop_scanning) return;
            
            if(is_port_open(ip, port, timeout)) {
                std::lock_guard<std::mutex> lock(result_mutex);
                open_ports.push_back(port);
                
                std::lock_guard<std::mutex> print_lock(print_mutex);
                std::cout << "\033[1;32m[*] " << port << " open\033[0m";
                auto it = well_known_ports.find(port);
                if(it != well_known_ports.end()) {
                    std::cout << " \033[1;33m(" << it->second << ")\033[0m";
                }
                if(show_version) {
                    std::string version = detect_version(ip, port, timeout);
                    if(version != "unknown") {
                        std::cout << " \033[1;36m" << version << "\033[0m";
                    }
                }
                std::cout << std::endl;
            }
            
            int current = scanned.fetch_add(1) + 1;
            if(show_progress && current % 50 == 0 && !stop_scanning) {
                std::lock_guard<std::mutex> print_lock(print_mutex);
                std::cout << "\r\033[1;34m[*] Progress: " << current << "/" << total << " ports scanned\033[0m" << std::flush;
            }
        });
    }
    
    while(scanned < total && !stop_scanning) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    if(show_progress && !stop_scanning) {
        std::lock_guard<std::mutex> print_lock(print_mutex);
        std::cout << "\r\033[1;34m[*] Progress: " << total << "/" << total << " ports scanned\033[0m" << std::endl;
    }
}

void print_animation() {
    const char* frames[] = {"◐", "◓", "◑", "◒"};
    static int frame = 0;
    std::cout << "\r\033[1;35m[*] Scanning " << frames[frame] << "\033[0m" << std::flush;
    frame = (frame + 1) % 4;
}

void print_banner() {
    std::cout << "\033[1;36m";
    std::cout << R"(
   ███████╗ ██████╗██████╗ ████████╗
   ██╔════╝██╔════╝██╔══██╗╚══██╔══╝
   ███████╗██║     ██████╔╝   ██║   
   ╚════██║██║     ██╔═══╝    ██║   
   ███████║╚██████╗██║        ██║   
   ╚══════╝ ╚═════╝╚═╝        ╚═╝   
                                     
   )" << std::endl;
}

void print_help() {
    std::cout << "\033[1;33mUsage: scpt <ip/hostname> [options]\033[0m" << std::endl;
    std::cout << "\n\033[1;36mOptions:\033[0m" << std::endl;
    std::cout << "  \033[1;32m-p <port>\033[0m            Single port scan" << std::endl;
    std::cout << "  \033[1;32m-p <port1,port2,...>\033[0m Multiple ports (comma separated)" << std::endl;
    std::cout << "  \033[1;32m-r <start> <end>\033[0m     Port range scan" << std::endl;
    std::cout << "  \033[1;32m-c\033[0m                   Scan common ports" << std::endl;
    std::cout << "  \033[1;32m-v\033[0m                   Show version detection" << std::endl;
    std::cout << "  \033[1;32m-t <ms>\033[0m              Timeout in milliseconds (default: 200)" << std::endl;
    std::cout << "  \033[1;32m-T <threads>\033[0m         Thread count (default: 100)" << std::endl;
    std::cout << "  \033[1;32m-P\033[0m                   Show progress" << std::endl;
    std::cout << "  \033[1;32m-s\033[0m                   Silent mode (no service names)" << std::endl;
    std::cout << "  \033[1;32m-h\033[0m                   Show this help" << std::endl;
    std::cout << std::endl;
    std::cout << "\033[1;36mExamples:\033[0m" << std::endl;
    std::cout << "  \033[1;35mscpt 127.0.0.1\033[0m           Scan all ports on localhost" << std::endl;
    std::cout << "  \033[1;35mscpt 127.0.0.1 -p 80\033[0m     Scan single port" << std::endl;
    std::cout << "  \033[1;35mscpt 127.0.0.1 -v\033[0m        Scan all ports with version detection" << std::endl;
    std::cout << "  \033[1;35mscpt 127.0.0.1 -p 22 -v\033[0m  Single port with version" << std::endl;
    std::cout << "  \033[1;35mscpt google.com -p 80 -v\033[0m Hostname scan with version" << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    print_banner();
    init_well_known_ports();
    
    if(argc < 2) {
        print_help();
        return 1;
    }
    
    std::string target = argv[1];
    std::string ip;
    bool silent = false;
    bool show_version = false;
    
    if(validate_ip(target)) {
        ip = target;
    } else if(validate_hostname(target)) {
        ip = resolve_hostname(target);
        if(ip.empty()) {
            std::cout << "\033[1;31m[!] Failed to resolve hostname: " << target << "\033[0m" << std::endl;
            return 1;
        }
        std::cout << "\033[1;33m[*] Resolved " << target << " to " << ip << "\033[0m" << std::endl;
    } else {
        std::cout << "\033[1;31m[!] Invalid IP address or hostname\033[0m" << std::endl;
        return 1;
    }
    
    int timeout = 200;
    int thread_count = 100;
    bool show_progress = false;
    bool common_scan = false;
    bool full_scan = false;
    std::vector<int> ports_to_scan;
    int start_port = -1;
    int end_port = -1;
    
    for(int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        
        if(arg == "-p" && i + 1 < argc) {
            std::string port_str = argv[++i];
            if(port_str.find(',') != std::string::npos) {
                std::stringstream ss(port_str);
                std::string port;
                while(std::getline(ss, port, ',')) {
                    int p = std::stoi(port);
                    if(is_valid_port(p)) {
                        ports_to_scan.push_back(p);
                    }
                }
            } else {
                int p = std::stoi(port_str);
                if(is_valid_port(p)) {
                    ports_to_scan.push_back(p);
                }
            }
        }
        else if(arg == "-r" && i + 2 < argc) {
            start_port = std::stoi(argv[++i]);
            end_port = std::stoi(argv[++i]);
            if(!is_valid_port(start_port) || !is_valid_port(end_port) || start_port > end_port) {
                std::cout << "\033[1;31m[!] Invalid port range\033[0m" << std::endl;
                return 1;
            }
        }
        else if(arg == "-v") {
            show_version = true;
        }
        else if(arg == "-t" && i + 1 < argc) {
            timeout = std::stoi(argv[++i]);
            if(timeout < 10) timeout = 10;
            if(timeout > 10000) timeout = 10000;
        }
        else if(arg == "-T" && i + 1 < argc) {
            thread_count = std::stoi(argv[++i]);
            if(thread_count < 1) thread_count = 1;
            if(thread_count > 1000) thread_count = 1000;
        }
        else if(arg == "-c") {
            common_scan = true;
        }
        else if(arg == "-P") {
            show_progress = true;
        }
        else if(arg == "-s") {
            silent = true;
        }
        else if(arg == "-h") {
            print_help();
            return 0;
        }
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Full scan if no port specified
    if(ports_to_scan.empty() && start_port == -1 && !common_scan) {
        full_scan = true;
        start_port = 1;
        end_port = 65535;
        std::cout << "\033[1;36m[*] Full port scan mode (1-65535)\033[0m" << std::endl;
    }
    
    if(common_scan) {
        std::vector<int> common_ports;
        for(auto& p : well_known_ports) {
            common_ports.push_back(p.first);
        }
        std::sort(common_ports.begin(), common_ports.end());
        
        std::vector<int> open_ports;
        ThreadPool pool(thread_count);
        
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        std::cout << "\033[1;33m[*] Scanning common ports on " << ip << "\033[0m" << std::endl;
        std::cout << "\033[1;34m[*] Using " << thread_count << " threads, " << timeout << "ms timeout\033[0m" << std::endl;
        
        scan_ports(ip, common_ports, pool, open_ports, timeout, show_progress, show_version);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        std::cout << "\033[1;32m[*] Total open ports: " << open_ports.size() << "\033[0m" << std::endl;
        std::cout << "\033[1;34m[*] Time taken: " << duration.count() << "ms\033[0m" << std::endl;
        return 0;
    }
    
    if(ports_to_scan.size() == 1) {
        int port = ports_to_scan[0];
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        std::cout << "\033[1;33m[*] Scanning port " << port << " on " << ip << "\033[0m" << std::endl;
        if(is_port_open(ip, port, timeout)) {
            std::cout << "\033[1;32m[*] " << port << " open\033[0m";
            if(!silent) {
                auto it = well_known_ports.find(port);
                if(it != well_known_ports.end()) {
                    std::cout << " \033[1;33m(" << it->second << ")\033[0m";
                }
            }
            if(show_version) {
                std::string version = detect_version(ip, port, timeout);
                if(version != "unknown") {
                    std::cout << " \033[1;36m" << version << "\033[0m";
                }
            }
            std::cout << std::endl;
        } else {
            std::cout << "\033[1;31m[*] " << port << " closed\033[0m" << std::endl;
        }
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        return 0;
    }
    
    if(!ports_to_scan.empty()) {
        std::vector<int> open_ports;
        ThreadPool pool(thread_count);
        
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        std::cout << "\033[1;33m[*] Scanning " << ports_to_scan.size() << " ports on " << ip << "\033[0m" << std::endl;
        std::cout << "\033[1;34m[*] Using " << thread_count << " threads, " << timeout << "ms timeout\033[0m" << std::endl;
        
        scan_ports(ip, ports_to_scan, pool, open_ports, timeout, show_progress, show_version);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        std::cout << "\033[1;32m[*] Total open ports: " << open_ports.size() << "\033[0m" << std::endl;
        std::cout << "\033[1;34m[*] Time taken: " << duration.count() << "ms\033[0m" << std::endl;
        return 0;
    }
    
    if(start_port > 0 && end_port > 0) {
        std::vector<int> open_ports;
        ThreadPool pool(thread_count);
        
        int total_ports = end_port - start_port + 1;
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        std::cout << "\033[1;33m[*] Scanning " << ip << " ports " << start_port << "-" << end_port << " (" << total_ports << " ports)\033[0m" << std::endl;
        std::cout << "\033[1;34m[*] Using " << thread_count << " threads, " << timeout << "ms timeout\033[0m" << std::endl;
        
        std::vector<int> port_list;
        for(int p = start_port; p <= end_port; ++p) {
            port_list.push_back(p);
        }
        
        scan_ports(ip, port_list, pool, open_ports, timeout, show_progress, show_version);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        std::cout << "\033[1;32m[*] Total open ports: " << open_ports.size() << "\033[0m" << std::endl;
        std::cout << "\033[1;34m[*] Time taken: " << duration.count() << "ms\033[0m" << std::endl;
        std::cout << "\033[1;36m--------\033[0m" << std::endl;
        return 0;
    }
    
    std::cout << "\033[1;31m[!] Invalid arguments. Use -h for help.\033[0m" << std::endl;
    return 1;
}
