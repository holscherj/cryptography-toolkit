#ifndef AES_H
#define AES_H

#include <string>
#include <memory>
#include <openssl/evp.h>

class AESEncryption {
  public:
    // Constructor
    AESEncryption();

    // Destructor
    ~AESEncryption() = default;

    std::string encrypt(const std::string& message) const;

    std::string decrypt(const std::string& encryptedMessage) const;

  private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx;
    std::string key;
    std::string iv;

    std::string crypt(const std::string& input, bool encrypt) const;

};

#endif