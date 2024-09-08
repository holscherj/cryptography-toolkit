#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <memory>
#include <openssl/evp.h>

class SHA256 {
  public:
    // Constructor
    SHA256();

    // Destructor
    ~SHA256() = default;

    // Hash Function
    std::string hash(const std::string& message) const;

  private:
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx;

};

#endif