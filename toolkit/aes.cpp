#include "aes.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

// Constructor
AESEncryption::AESEncryption():
  ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free), key("32"), iv("16") {}

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
