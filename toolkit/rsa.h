#ifndef RSA_H
#define RSA_H

#include <string>
#include <memory>
#include <openssl/evp.h>

class RSAEncryption {
public:
    // Constructor
    RSAEncryption(int keyLength);

    // Destructor
    ~RSAEncryption() = default;

    // Method to generate keys
    void generateKeys();

    // Method to get the public key as a string
    std::string getPublicKey() const;

    // Method to get the private key as a string
    std::string getPrivateKey() const;

    // Method to encrypt a message
    std::string encrypt(const std::string& message) const;

    // Method to decrypt a message
    std::string decrypt(const std::string& encryptedMessage) const;

private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey;
    int keyLength;

    // Utility function to convert key to string
    std::string keyToString(EVP_PKEY* key) const;
};

#endif