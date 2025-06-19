
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <map>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "peer_discovery.hpp"
#include "json.hpp"

#define CHUNK_SIZE 1024
#define META_EXT ".meta"
#define AES_KEYLEN 32
#define AES_IVLEN 16
#define KEYS_FOLDER "keys/"

#define RESET       "\033[0m"
#define RED         "\033[31m"
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define BLUE        "\033[34m"
#define CYAN        "\033[36m"
#define BOLDWHITE   "\033[1m\033[37m"

#define LOG_INFO(msg)    std::cout << BLUE << "[INFO] " << RESET << msg << std::endl
#define LOG_SUCCESS(msg) std::cout << GREEN << "[SUCCESS] " << RESET << msg << std::endl
#define LOG_ERROR(msg)   std::cout << RED << "[ERROR] " << RESET << msg << std::endl
#define LOG_REQUEST(msg) std::cout << CYAN << "[REQUEST] " << RESET << msg << std::endl
#define LOG_SENDING(msg) std::cout << YELLOW << "[SENDING] " << RESET << msg << std::endl

std::map<std::string, std::pair<std::string, int>> connectedPeers;

bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

size_t getResumeOffset(const std::string& filename) {
    std::ifstream meta("metadata/" + filename + META_EXT);
    if (!meta) return 0;
    size_t offset;
    meta >> offset;
    return offset;
}

void updateResumeOffset(const std::string& filename, size_t offset) {
    std::ofstream meta("metadata/" + filename + META_EXT, std::ios::trunc);
    meta << offset;
}

RSA* loadPublicKey(const std::string& filepath) {
    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) return nullptr;
    RSA* rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

RSA* loadPrivateKey(const std::string& filepath) {
    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) return nullptr;
    RSA* rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

void sendEncryptedKeyAndIV(int sock, const unsigned char* key, const unsigned char* iv, const std::string& pubKeyPath) {
    RSA* rsa = loadPublicKey(pubKeyPath);
    if (!rsa) {
        LOG_ERROR("Failed to load public RSA key.");
        return;
    }
    unsigned char encryptedKey[256], encryptedIV[256];
    int keyLen = RSA_public_encrypt(AES_KEYLEN, key, encryptedKey, rsa, RSA_PKCS1_OAEP_PADDING);
    int ivLen = RSA_public_encrypt(AES_IVLEN, iv, encryptedIV, rsa, RSA_PKCS1_OAEP_PADDING);

    send(sock, &keyLen, sizeof(int), 0);
    send(sock, encryptedKey, keyLen, 0);
    send(sock, &ivLen, sizeof(int), 0);
    send(sock, encryptedIV, ivLen, 0);
    RSA_free(rsa);
}

bool aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                 unsigned char *iv, unsigned char *ciphertext, int &out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!ctx) return false;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return false;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return false;
    out_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return false;
    out_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                 unsigned char *iv, unsigned char *plaintext, int &out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!ctx) return false;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return false;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return false;
    out_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return false;
    out_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void sendFileChunks(int clientSocket, const std::string& filename) {
    std::ifstream file("shared/" + filename, std::ios::binary);
    if (!file) {
        LOG_ERROR("Unable to open file: " + filename);
        return;
    }

    unsigned char aes_key[AES_KEYLEN], aes_iv[AES_IVLEN];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(aes_iv, sizeof(aes_iv));

    sendEncryptedKeyAndIV(clientSocket, aes_key, aes_iv, KEYS_FOLDER + std::string("peer_public.pem"));

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    size_t resumeOffset = getResumeOffset(filename);
    if (resumeOffset > 0) {
        file.seekg(resumeOffset);
        LOG_INFO("Resuming file from byte offset: " + std::to_string(resumeOffset));
    }

    char buffer[CHUNK_SIZE];
    unsigned char cipherbuf[CHUNK_SIZE * 2];
    size_t bytesSent = resumeOffset;
    int chunkIndex = resumeOffset / CHUNK_SIZE;

    while (!file.eof()) {
        file.read(buffer, CHUNK_SIZE);
        size_t bytesRead = file.gcount();
        if (bytesRead == 0) break;

        int encryptedLen;
        aes_encrypt((unsigned char*)buffer, bytesRead, aes_key, aes_iv, cipherbuf, encryptedLen);
        send(clientSocket, cipherbuf, encryptedLen, 0);
        bytesSent += bytesRead;
        updateResumeOffset(filename, bytesSent);
        std::cout << YELLOW << " [Chunk " << ++chunkIndex << "] " << bytesRead << " bytes sent..." << RESET << std::endl;
    }

    LOG_SUCCESS("File '" + filename + "' successfully sent");
    std::filesystem::remove("metadata/" + filename + META_EXT);
    file.close();
}

void handleIncomingRequest(int serverSocket) {
    sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);

    while (true) {
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            LOG_ERROR("Failed to accept connection.");
            continue;
        }

        char fileRequest[1024] = {0};
        recv(clientSocket, fileRequest, sizeof(fileRequest), 0);

        std::string requesterIP = inet_ntoa(clientAddr.sin_addr);
        int requesterPort = ntohs(clientAddr.sin_port);
        std::string filename(fileRequest);

        if (filename.rfind("__probe__", 0) == 0) {
            std::string probeFile = filename.substr(9);
            std::string filepath = "shared/" + probeFile;
            std::string response = fileExists(filepath) ? "FOUND" : "NOTFOUND";
            send(clientSocket, response.c_str(), response.length(), 0);
            close(clientSocket);
            continue;
        }

        LOG_REQUEST("Received file request: '" + filename + "' from " + requesterIP + ":" + std::to_string(requesterPort));

        if (!fileExists("shared/" + filename)) {
            LOG_ERROR("File '" + filename + "' not found in shared folder.");
            close(clientSocket);
            continue;
        }

        LOG_INFO("File '" + filename + "' found. Preparing to send...");
        LOG_SENDING("Transmitting file to peer...");
        sendFileChunks(clientSocket, filename);
        close(clientSocket);
    }
}

void requestFile(const std::string& peerIP, int peerPort, const std::string& filename) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in peerAddr;
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(peerPort);
    inet_pton(AF_INET, peerIP.c_str(), &peerAddr.sin_addr);

    if (connect(sock, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) < 0) {
        LOG_ERROR("Failed to connect to peer " + peerIP);
        return;
    }

    send(sock, filename.c_str(), filename.length(), 0);

    int keyLen, ivLen;
    recv(sock, &keyLen, sizeof(int), 0);
    unsigned char encryptedKey[256];
    recv(sock, encryptedKey, keyLen, 0);

    recv(sock, &ivLen, sizeof(int), 0);
    unsigned char encryptedIV[256];
    recv(sock, encryptedIV, ivLen, 0);

    RSA* rsa = loadPrivateKey(KEYS_FOLDER + std::string("peer_private.pem"));
    unsigned char aes_key[AES_KEYLEN], aes_iv[AES_IVLEN];
    RSA_private_decrypt(keyLen, encryptedKey, aes_key, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_private_decrypt(ivLen, encryptedIV, aes_iv, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    std::ofstream outFile("downloads/" + filename, std::ios::binary | std::ios::app);
    unsigned char buffer[CHUNK_SIZE * 2], plainbuf[CHUNK_SIZE * 2];
    ssize_t bytesReceived;

    while ((bytesReceived = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        int decryptedLen;
        aes_decrypt(buffer, bytesReceived, aes_key, aes_iv, plainbuf, decryptedLen);
        outFile.write((char*)plainbuf, decryptedLen);
        std::cout << GREEN << "[Chunk Received: " << decryptedLen << " bytes]" << RESET << std::endl;
    }

    LOG_SUCCESS("File '" + filename + "' received successfully.");
    outFile.close();
    close(sock);
}

void showMenu() {
    std::cout << BOLDWHITE << "\n==== P2P File Sharing Menu ====" << RESET << std::endl;
    std::cout << "1. Request a file\n2. View connected peers\n3. Exit\n";
    std::cout << "Choose an option: ";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: ./peer <port> <peer_name>\n";
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string peerName = argv[2];

    LOG_INFO(peerName + " started on port " + std::to_string(port));

    connectedPeers = loadPeersFromJSON("known_peers.json");

    LOG_INFO("Connected peers:");
    for (const auto& peer : connectedPeers) {
        std::cout << "       -> " << peer.first << " @ " << peer.second.first << ":" << peer.second.second << std::endl;
    }

    std::filesystem::create_directories("downloads");
    std::filesystem::create_directories("metadata");
    std::filesystem::create_directories("shared");
    std::filesystem::create_directories("keys");

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSocket, 5);

    std::thread listenerThread(handleIncomingRequest, serverSocket);

    while (true) {
        showMenu();
        int choice;
        std::cin >> choice;
        if (choice == 1) {
            std::string fileReq;
            std::cout << "Enter filename to request: ";
            std::cin >> fileReq;
            std::string foundIP;
            int foundPort;
            if (dfsFileSearch(fileReq, connectedPeers, foundIP, foundPort)) {
                requestFile(foundIP, foundPort, fileReq);
            } else {
                LOG_ERROR("File not found in any known peer.");
            }
        } else if (choice == 2) {
            for (const auto& peer : connectedPeers) {
                std::cout << "       -> " << peer.first << " @ " << peer.second.first << ":" << peer.second.second << std::endl;
            }
        } else if (choice == 3) break;
    }

    close(serverSocket);
    listenerThread.join();
    return 0;
}

