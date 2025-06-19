#include "crypto_utils.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <cstring>
#include <fstream>
#include <iostream>

EVP_PKEY* loadPublicKey(const std::string& filepath) {
    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) return nullptr;
    EVP_PKEY* pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pubkey;
}

EVP_PKEY* loadPrivateKey(const std::string& filepath) {
    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) return nullptr;
    EVP_PKEY* privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return privkey;
}

bool encryptWithPublicKey(EVP_PKEY* pubkey, const unsigned char* in, size_t in_len,
                          unsigned char* out, size_t& out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) return false;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) return false;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return false;

    size_t tmp_len = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &tmp_len, in, in_len) <= 0) return false;

    if (EVP_PKEY_encrypt(ctx, out, &tmp_len, in, in_len) <= 0) return false;
    out_len = tmp_len;

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool decryptWithPrivateKey(EVP_PKEY* privkey, const unsigned char* in, size_t in_len,
                           unsigned char* out, size_t& out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) return false;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) return false;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return false;

    size_t tmp_len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &tmp_len, in, in_len) <= 0) return false;

    if (EVP_PKEY_decrypt(ctx, out, &tmp_len, in, in_len) <= 0) return false;
    out_len = tmp_len;

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool aes_encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
                 unsigned char* iv, unsigned char* ciphertext, int& out_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return false;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) return false;
    out_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) return false;
    out_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
                 unsigned char* iv, unsigned char* plaintext, int& out_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return false;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) return false;
    out_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) return false;
    out_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
