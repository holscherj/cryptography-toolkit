#include "aes.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

// Constructor
AESEncryption::AESEncryption(const std::string& key, const std::string& iv):
  ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free), key(key), iv(iv) {
    if(key.size() != 32 || iv.size() != 16) {
      throw std::runtime_error("Invalid Key or IV size. Please use a 32-byte key and a 16-byte IV.");
    }
}

std::string AESEncryption::encrypt(const std::string& message) const {
  return crypt(message, true);
}

std::string AESEncryption::decrypt(const std::string& encryptedMessage) const {
  return crypt(encryptedMessage, false);
}

std::string AESEncryption::crypt(const std::string& input, bool encrypt) const {
  int len;
  int ciphertextLen;
  std::string output(input.size() + AES_BLOCK_SIZE, '\0');

  if(encrypt) {
    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()))) {
      throw std::runtime_error("Error initializing AES encryption.");
    }
  } else {
    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()))) {
      throw std::runtime_error("Error initializing AES decryption.");
    }
  }

  if(encrypt) {
    if (1 != EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(&output[0]), &len, reinterpret_cast<const unsigned char*>(input.c_str()), input.size())) {
      throw std::runtime_error("Error during AES encryption.");
    }
  } else {
    if (1 != EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(&output[0]), &len, reinterpret_cast<const unsigned char*>(input.c_str()), input.size())) {
      throw std::runtime_error("Error during AES decryption.");
    }
  }
  ciphertextLen = len;

  if (encrypt) {
    if (1 != EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(&output[0]) + len, &len)) {
      throw std::runtime_error("Error finalizing AES encryption.");
    }
  } else {
    if (1 != EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(&output[0]) + len, &len)) {
      throw std::runtime_error("Error finalizing AES decryption.");
    }
  }
  ciphertextLen += len;
  output.resize(ciphertextLen);

  return output;
}
