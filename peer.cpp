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
#include <sstream>
#include <limits>
#include "peer_discovery.hpp"
#include "json.hpp"
#include "crypto_utils.hpp"
#include <openssl/rand.h>
#include <atomic>

#define CHUNK_SIZE 1024
#define META_EXT ".meta"
#define KEYS_FOLDER "keys/"

#define RESET       "\033[0m"
#define RED         "\033[31m"
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define BLUE        "\033[34m"
#define CYAN        "\033[36m"
#define BOLDWHITE   "\033[1m\033[37m"

#define LOG_INFO(msg)    std::cout << BLUE << "[INFO] " << RESET << msg << std::endl << std::flush
#define LOG_SUCCESS(msg) std::cout << GREEN << "[SUCCESS] " << RESET << msg << std::endl<< std::flush
#define LOG_ERROR(msg)   std::cout << RED << "[ERROR] " << RESET << msg << std::endl<< std::flush
#define LOG_REQUEST(msg) std::cout << CYAN << "[REQUEST] " << RESET << msg << std::endl<< std::flush
#define LOG_SENDING(msg) std::cout << YELLOW << "[SENDING] " << RESET << msg << std::endl<< std::flush

std::map<std::string, std::pair<std::string, int>> connectedPeers;
std::string globalPeerName;
std::atomic<bool> isRunning(true);

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

void sendEncryptedKeyAndIV(int sock, const unsigned char* key, const unsigned char* iv, const std::string& pubKeyPath) {
    EVP_PKEY* pubkey = loadPublicKey(pubKeyPath);
    if (!pubkey) {
        LOG_ERROR("Failed to load public key.");
        return;
    }

    unsigned char encryptedKey[512], encryptedIV[512];
    size_t keyLen, ivLen;

    if (!encryptWithPublicKey(pubkey, key, AES_KEYLEN, encryptedKey, keyLen) ||
        !encryptWithPublicKey(pubkey, iv, AES_IVLEN, encryptedIV, ivLen)) {
        LOG_ERROR("RSA encryption failed.");
        EVP_PKEY_free(pubkey);
        return;
    }

    send(sock, &keyLen, sizeof(size_t), 0);
    send(sock, encryptedKey, keyLen, 0);
    send(sock, &ivLen, sizeof(size_t), 0);
    send(sock, encryptedIV, ivLen, 0);

    EVP_PKEY_free(pubkey);
    LOG_SUCCESS("Encrypted AES key and IV sent successfully.");
}

void sendFileChunks(int clientSocket, const std::string& filename) {
    std::ifstream file("shared/" + filename, std::ios::binary);
    if (!file) {
        LOG_ERROR("Unable to open file: " + filename);
        return;
    }

    LOG_INFO("Started sending file: '" + filename + "'");

    unsigned char aes_key[AES_KEYLEN], aes_iv[AES_IVLEN];
    RAND_bytes(aes_key, AES_KEYLEN);
    RAND_bytes(aes_iv, AES_IVLEN);

    sendEncryptedKeyAndIV(clientSocket, aes_key, aes_iv, KEYS_FOLDER + globalPeerName + "_public.pem");

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
        LOG_INFO("[Chunk " + std::to_string(++chunkIndex) + "] Sent " + std::to_string(bytesRead) + " bytes");
    }

    LOG_SUCCESS("File '" + filename + "' successfully sent");
    std::filesystem::remove("metadata/" + filename + META_EXT);
    file.close();
}

void handleIncomingRequest(int serverSocket) {
    sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);

    LOG_INFO("Listener thread started.");

    while (isRunning) {
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);

        if (!isRunning || clientSocket < 0) {
            if (!isRunning) break;
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

    LOG_INFO("Listener thread exited cleanly.");
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

    size_t keyLen, ivLen;
    recv(sock, &keyLen, sizeof(size_t), 0);
    unsigned char encryptedKey[512];
    recv(sock, encryptedKey, keyLen, 0);

    recv(sock, &ivLen, sizeof(size_t), 0);
    unsigned char encryptedIV[512];
    recv(sock, encryptedIV, ivLen, 0);

    EVP_PKEY* privkey = loadPrivateKey(KEYS_FOLDER + globalPeerName + "_private.pem");
    if (!privkey) {
        LOG_ERROR("Private key not found or failed to load.");
        return;
    }

    unsigned char aes_key[AES_KEYLEN], aes_iv[AES_IVLEN];
    size_t outLen1, outLen2;

    if (!decryptWithPrivateKey(privkey, encryptedKey, keyLen, aes_key, outLen1) ||
        !decryptWithPrivateKey(privkey, encryptedIV, ivLen, aes_iv, outLen2)) {
        LOG_ERROR("RSA decryption failed.");
        EVP_PKEY_free(privkey);
        return;
    }
    EVP_PKEY_free(privkey);

    std::ofstream outFile("downloads/" + filename, std::ios::binary | std::ios::app);
    unsigned char buffer[CHUNK_SIZE * 2], plainbuf[CHUNK_SIZE * 2];
    ssize_t bytesReceived;

    LOG_SUCCESS("Received and decrypted AES key and IV successfully.");

    while ((bytesReceived = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        int decryptedLen;
        aes_decrypt(buffer, bytesReceived, aes_key, aes_iv, plainbuf, decryptedLen);
        outFile.write((char*)plainbuf, decryptedLen);
        LOG_SUCCESS("[Chunk Received: " + std::to_string(decryptedLen) + " bytes]");
    }

    LOG_SUCCESS("File '" + filename + "' received successfully.");
    outFile.close();
    close(sock);
}

void showMenu() {
    std::cout << BOLDWHITE << "\n==== P2P File Sharing Menu ====\n" << RESET;
    std::cout << "1. Request a file\n2. View connected peers\n3. Back to menu\n4. Exit\n";
    std::cout << "Choose an option: ";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: ./peer <port> <peer_name>\n";
        return 1;
    }

    int port;
    std::string peerName;

restart:
    port = std::stoi(argv[1]);
    peerName = argv[2];
    globalPeerName = peerName;

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

    isRunning = true;
    std::thread listenerThread(handleIncomingRequest, serverSocket);

    while (true) {
        showMenu();
        int choice;
        std::string input;
        std::getline(std::cin, input);
        std::stringstream ss(input);

        if (!(ss >> choice)) {
            LOG_ERROR("Invalid input. Please enter a number.");
            continue;
        }

        if (choice == 1) {
            std::string fileReq;
            std::cout << "Enter filename to request: ";
            std::cin >> fileReq;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
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
        } else if (choice == 3) {
            LOG_INFO("Returning to menu...");
            continue;
        } else if (choice == 4) {
            LOG_INFO("Shutting down peer. Please wait...");
            isRunning = false;
            shutdown(serverSocket, SHUT_RDWR);
            close(serverSocket);
            break;
        } else {
            LOG_ERROR("Invalid choice. Please select 1, 2, 3, or 4.");
        }
    }

    listenerThread.join();
    LOG_SUCCESS("Peer " + globalPeerName + " exited.");

    std::string restartChoice;
    std::cout << "Do you want to restart the peer session? (y/n): ";
    std::getline(std::cin, restartChoice);
    if (restartChoice == "y" || restartChoice == "Y") {
        goto restart;
    }

    return 0;
}
    
