#include "peer_discovery.hpp"
#include "json.hpp"
#include <fstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

using json = nlohmann::json;

std::map<std::string, std::pair<std::string, int>> loadPeersFromJSON(const std::string& filepath) {
    std::ifstream f(filepath);
    std::map<std::string, std::pair<std::string, int>> result;
    if (!f.is_open()) return result;
    
    json j;
    f >> j;
    for (auto& [name, peer] : j.items()) {
        result[name] = { peer["ip"], peer["port"] };
    }
    return result;
}

bool dfsFileSearch(const std::string& filename, const std::map<std::string, std::pair<std::string, int>>& peers, std::string& foundIP, int& foundPort) {
    for (const auto& [name, info] : peers) {
        const std::string& ip = info.first;
        int port = info.second;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            continue;
        }

        std::string probe = "__probe__" + filename;
        send(sock, probe.c_str(), probe.size(), 0);
        char response[8] = {0};
        recv(sock, response, sizeof(response), 0);
        close(sock);

        if (std::string(response) == "FOUND") {
            foundIP = ip;
            foundPort = port;
            return true;
        }
    }
    return false;
}
