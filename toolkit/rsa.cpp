#include "rsa.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <openssl/err.h>
#include <openssl/pem.h>

// Constructor
RSAEncryption::RSAEncryption(int keyLength)
    : pkey(nullptr, EVP_PKEY_free), keyLength(keyLength) {
    if keyLen
    generateKeys();
}

// Method to generate keys
void RSAEncryption::generateKeys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        throw std::runtime_error("Error creating context for key generation");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error initializing key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyLength) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error setting RSA key length");
    }

    EVP_PKEY* temp_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &temp_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error generating RSA key");
    }

    pkey.reset(temp_pkey);
    EVP_PKEY_CTX_free(ctx);
}

// Method to get the public key as a string
std::string RSAEncryption::getPublicKey() const {
    return keyToString(pkey.get());
}

// Method to get the private key as a string
std::string RSAEncryption::getPrivateKey() const {
    std::ostringstream keyStream;
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey.get(), NULL, NULL, 0, NULL, NULL);

    char* keyData;
    long keyLength = BIO_get_mem_data(bio, &keyData);
    keyStream.write(keyData, keyLength);
    BIO_free(bio);

    return keyStream.str();
}

// Method to encrypt a message
std::string RSAEncryption::encrypt(const std::string& message) const {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey.get(), NULL);
    if (!ctx) {
        throw std::runtime_error("Error creating context for encryption");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error initializing encryption");
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error determining buffer size for encryption");
    }

    std::string encrypted(outlen, '\0');
    if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char*>(&encrypted[0]), &outlen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error during encryption");
    }

    encrypted.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

// Method to decrypt a message
std::string RSAEncryption::decrypt(const std::string& encryptedMessage) const {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey.get(), NULL);
    if (!ctx) {
        throw std::runtime_error("Error creating context for decryption");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error initializing decryption");
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), encryptedMessage.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error determining buffer size for decryption");
    }

    std::string decrypted(outlen, '\0');
    if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(&decrypted[0]), &outlen, reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), encryptedMessage.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error during decryption");
    }

    decrypted.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

// Utility function to convert key to string
std::string RSAEncryption::keyToString(EVP_PKEY* key) const {
    std::ostringstream keyStream;
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, key);

    char* keyData;
    long keyLength = BIO_get_mem_data(bio, &keyData);
    keyStream.write(keyData, keyLength);
    BIO_free(bio);

    return keyStream.str();
}
