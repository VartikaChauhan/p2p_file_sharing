// crypto_utils.hpp
#pragma once

#include <string>
#include <openssl/evp.h>

#define AES_KEYLEN 32
#define AES_IVLEN 16

EVP_PKEY* loadPublicKey(const std::string& filepath);
EVP_PKEY* loadPrivateKey(const std::string& filepath);

bool encryptWithPublicKey(EVP_PKEY* pubkey, const unsigned char* in, size_t in_len,
                          unsigned char* out, size_t& out_len);

bool decryptWithPrivateKey(EVP_PKEY* privkey, const unsigned char* in, size_t in_len,
                            unsigned char* out, size_t& out_len);

bool aes_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
                 unsigned char* iv, unsigned char* ciphertext, int& out_len);

bool aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
                 unsigned char* iv, unsigned char* plaintext, int& out_len);
