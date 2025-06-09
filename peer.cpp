#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <queue>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include "json.hpp"

using json = nlohmann::json;

#define BUFFER_SIZE 4096

std::mutex io_mutex;

struct PeerInfo {
    std::string ip;
    int port;
};

std::unordered_map<std::string, PeerInfo> load_peers(const std::string& filename) {
    std::unordered_map<std::string, PeerInfo> peers;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cerr << "Failed to open peer file: " << filename << std::endl;
        return peers;
    }

    json j;
    try {
        file >> j;
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        return peers;
    }

    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string id = it.key();
        auto val = it.value();
        if (!val.contains("ip") || !val.contains("port")) {
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cerr << "Invalid entry for " << id << ": missing ip or port\n";
            continue;
        }
        std::string ip = val["ip"];
        int port = val["port"];
        peers[id] = {ip, port};
    }

    return peers;
}

EVP_PKEY* load_key(const std::string& filename, bool is_private) {
    FILE* fp = fopen(filename.c_str(), "r");
    if (!fp) return nullptr;
    EVP_PKEY* pkey = is_private ? PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr)
                                 : PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}

std::vector<unsigned char> rsa_encrypt(EVP_PKEY* pubkey, const unsigned char* data, size_t len) {
    std::vector<unsigned char> out;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    size_t outlen;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) return out;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return out;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, data, len) <= 0) return out;
    out.resize(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, data, len) <= 0) return {};
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> rsa_decrypt(EVP_PKEY* privkey, const unsigned char* enc_data, size_t len) {
    std::vector<unsigned char> out;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    size_t outlen;
    if (EVP_PKEY_decrypt_init(ctx) <= 0) return out;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return out;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, enc_data, len) <= 0) return out;
    out.resize(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, enc_data, len) <= 0) return {};
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> aes_encrypt(const unsigned char* data, int len, const unsigned char* key, const unsigned char* iv) {
    std::vector<unsigned char> out(len + EVP_MAX_BLOCK_LENGTH);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, out.data(), &outlen1, data, len);
    EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    out.resize(outlen1 + outlen2);
    return out;
}

std::vector<unsigned char> aes_decrypt(const unsigned char* enc_data, int len, const unsigned char* key, const unsigned char* iv) {
    std::vector<unsigned char> out(len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_DecryptUpdate(ctx, out.data(), &outlen1, enc_data, len);
    EVP_DecryptFinal_ex(ctx, out.data() + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    out.resize(outlen1 + outlen2);
    return out;
}

void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
    buffer[bytes] = '\0';
    std::string filename(buffer);
    std::string filepath = "shared/" + filename;

    if (!std::filesystem::exists(filepath)) {
        send(client_sock, "FILE_NOT_FOUND", 15, 0);
    } else {
        {
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cout << "Sending file " << filename << " to requesting peer\n";
        }

        std::ifstream file(filepath, std::ios::binary);
        while (!file.eof()) {
            file.read(buffer, BUFFER_SIZE);
            send(client_sock, buffer, file.gcount(), 0);
        }
    }
    close(client_sock);
}

void server_thread(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(server_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        return;
    }

    if (listen(server_sock, 5) < 0) {
        perror("listen failed");
        return;
    }

    while (true) {
        int client_sock = accept(server_sock, nullptr, nullptr);
        if (client_sock < 0) {
            perror("accept failed");
            continue;
        }
        std::thread(handle_client, client_sock).detach();
    }
}

void client_thread(const std::string& peer_ip, int port, const std::string& filename) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, peer_ip.c_str(), &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cerr << "Connection failed to " << peer_ip << ":" << port << std::endl;
        return;
    }

    send(sock, filename.c_str(), filename.size(), 0);
    {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << "File found on remote peer\n" << "Downloading...\n";
    }

    std::ofstream outfile("downloads/" + filename, std::ios::binary);
    char buffer[BUFFER_SIZE];
    int bytes;
    while ((bytes = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        outfile.write(buffer, bytes);
    }
    {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << "Decryption complete\n" << "File saved in downloads/" << filename << std::endl;
    }
    close(sock);
}

int main(int argc, char* argv[]) {
    std::string peer_name = "peer1";
    int port = 5001;
    if (argc > 1) peer_name = argv[1];
    if (argc > 2) port = std::stoi(argv[2]);

    {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << "Starting " << peer_name << " on port " << port << std::endl;
    }

    std::filesystem::create_directory("shared");
    std::filesystem::create_directory("downloads");
    std::thread(server_thread, port).detach();
    std::this_thread::sleep_for(std::chrono::seconds(2));

    EVP_PKEY* pub = load_key("keys/public.pem", false);
    EVP_PKEY* priv = load_key("keys/private.pem", true);

    std::string msg = "P2P Initialisation begins !";
    auto encrypted = rsa_encrypt(pub, (unsigned char*)msg.c_str(), msg.size());
    auto decrypted = rsa_decrypt(priv, encrypted.data(), encrypted.size());
    {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << "Decrypted RSA message: " << std::string(decrypted.begin(), decrypted.end()) << "\n";
    }

    unsigned char aes_key[32];
    unsigned char iv[16];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));
    auto aes_enc = aes_encrypt((unsigned char*)msg.c_str(), msg.size(), aes_key, iv);
    auto aes_dec = aes_decrypt(aes_enc.data(), aes_enc.size(), aes_key, iv);
    {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << "Decrypted AES message: " << std::string(aes_dec.begin(), aes_dec.end()) << "\n";
    }

    auto peers = load_peers("known_peers.json");
    for (const auto& [id, info] : peers) {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << id << " -> " << info.ip << ":" << info.port << "\n";
    }

    while (true) {
        std::string filename;
        {
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cout << "Enter filename to download (or 'exit' to quit): " << std::flush;
        }

        std::cin >> filename;

        if (!std::cin) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cerr << "Input error. Please try again.\n";
            continue;
        }

        if (filename == "exit") break;

        std::vector<std::thread> threads;
        for (const auto& [id, peer] : peers) {
            threads.emplace_back(client_thread, peer.ip, peer.port, filename);
        }
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
    }

    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    return 0;
}



