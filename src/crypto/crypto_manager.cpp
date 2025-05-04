#include "crypto/cryptoManager.h"
#include <iostream>
#include <openssl/err.h>
#include <openssl/rand.h>

CryptoManager::CryptoManager(): encrypt_ctx_(EVP_CIPHER_CTX_new()), decrypt_ctx_(EVP_CIPHER_CTX_new()) {
    if (!encrypt_ctx_ || !decrypt_ctx_) {
        std::cerr << "Failed to create cipher contexts" << std::endl;
    }
}

CryptoManager::~CryptoManager() {
    if (encrypt_ctx_) {
        EVP_CIPHER_CTX_free(encrypt_ctx_);
    }
    if (decrypt_ctx_) {
        EVP_CIPHER_CTX_free(decrypt_ctx_);
    }
}

bool CryptoManager::initialize(const std::string &psk) {
    if (!encrypt_ctx_ || !decrypt_ctx_) {
        std::cerr << "Cipher contexts not initialized" << std::endl;
        return false;
    }

    key_.assign(psk.begin(), psk.end());
    if (key_.size() != 32) {
        std::cerr << "Invalid PSK size" << std::endl;
        return false;
    }

    return true;
}

std::vector<uint8_t> CryptoManager::encrypt(const std::vector<uint8_t> &plaintext){
    //generate random nonce
    std::vector<uint8_t> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
        std::cerr<< "Failed to generate random IV" << std::endl;
        return {};
    }

    std::cout << "Generated IV: " << std::endl;

    //initalize encrpytion operation

    if (EVP_EncryptInit_ex(encrypt_ctx_, EVP_aes_256_gcm(), nullptr,
        key_.data(), iv.data()) != 1)  {
        std::cerr << "Failed to initialize encryption" << std::endl;
        return {};
    }

    int outlen;
    std::vector<uint8_t> ciphertext(plaintext.size() + BLOCK_SIZE);
    if (EVP_EncryptUpdate(encrypt_ctx_, ciphertext.data(), &outlen,
            plaintext.data(), plaintext.size()) != 1) {
        std::cerr << "Failed to update encryption" << std::endl;
        return {};
    }

    int templen;
    if (EVP_EncryptFinal_ex(encrypt_ctx_, ciphertext.data() + outlen, &templen) != 1) {
        std::cerr << "Failed to finalize encryption" << std::endl;
        return {};
    }

    outlen += templen;
    ciphertext.resize(outlen);

    std::vector<uint8_t> tag(TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(encrypt_ctx_, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
        std::cerr << "Failed to get tag" << std::endl;
        return {};
    }

    std::vector<uint8_t> result;

    result.reserve(IV_SIZE + ciphertext.size() + TAG_SIZE);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());

    return result;

}


std::vector<uint8_t> CryptoManager::decrypt(const std::vector<uint8_t>& ciphertext){
    if (ciphertext.size() < IV_SIZE + TAG_SIZE) {
            std::cerr << "Ciphertext too short" << std::endl;
            return {};
        }

    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
    std::vector<uint8_t> tag(ciphertext.end() - TAG_SIZE, ciphertext.end());
    std::vector<uint8_t> actual_cipher_text(ciphertext.begin()+IV_SIZE, ciphertext.end()-TAG_SIZE);


    if (iv.size() != IV_SIZE) {
        std::cerr << "Invalid IV size" << std::endl;
        return {};
    }

    if (EVP_DecryptInit_ex(decrypt_ctx_, EVP_aes_256_gcm(), nullptr,
        key_.data(), iv.data()) != 1) {
        std::cerr << "Failed to initialize decryption" << std::endl;
        return {};
    }

    if (EVP_CIPHER_CTX_ctrl(decrypt_ctx_, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
        std::cerr << "Failed to set tag" << std::endl;
        return {};
    }

    int outlen;
    std::vector<uint8_t> plaintext(actual_cipher_text.size());
    if (EVP_DecryptUpdate(decrypt_ctx_, plaintext.data(), &outlen,
            actual_cipher_text.data(), actual_cipher_text.size()) != 1) {
        std::cerr << "Failed to update decryption" << std::endl;
        return {};
    }

    int templen;
    if (EVP_DecryptFinal_ex(decrypt_ctx_, plaintext.data() + outlen, &templen) != 1) {
        std::cerr << "Failed to finalize decryption" << std::endl;
        return {};
    }

    outlen += templen;
    plaintext.resize(outlen);




    return plaintext;

}

std::string CryptoManager::generate_key(size_t len){
    std::vector<uint8_t> key(len);
    if (RAND_bytes(key.data(), len) != 1) {
        std::cerr << "Failed to generate key" << std::endl;
        return "";
    }
    return std::string(key.begin(), key.end());

}
