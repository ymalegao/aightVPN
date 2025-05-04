#pragma once
#include <vector>
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

class CryptoManager{
    public:
        CryptoManager();
        ~CryptoManager();
        bool initialize(const std::string& psk);
        std::vector<uint8_t> encrypt(const std::vector<uint8_t>&  plaintext);
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);

        static std::string generate_key(size_t len = 32);
    private:
        std::vector<uint8_t> key_;
        static constexpr size_t IV_SIZE = 12;
        static constexpr size_t TAG_SIZE = 16;
        static constexpr size_t BLOCK_SIZE = 16;

        EVP_CIPHER_CTX* encrypt_ctx_;
        EVP_CIPHER_CTX* decrypt_ctx_;
};
