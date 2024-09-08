#include "sha256.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>

SHA256::SHA256() : ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free) {
  if(!ctx) {
    throw std::runtime_error("Failed to create SHA-256 context");
  }
}

std::string SHA256::hash(const std::string& message) const {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int lengthOfHash = 0;

  if(1 != EVP_DigestInit_ex(ctx.get(), EVP_sha256(), NULL)) {
    throw std::runtime_error("Error initializing SHA-256 context");
  }

  if(1 != EVP_DigestUpdate(ctx.get(), message.c_str(), message.size())) {
    throw std::runtime_error("Error updating SHA-256 context");
  }

  if(1 != EVP_DigestFinal_ex(ctx.get(), hash, &lengthOfHash)) {
    throw std::runtime_error("Error finalizing SHA-256 hash");
  }

  std::ostringstream oss;
  for(unsigned int i = 0; i < lengthOfHash; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  }

  return oss.str();

}