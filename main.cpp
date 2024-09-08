#include <iostream>
#include <string>
#include "toolkit/rsa.h"
#include "toolkit/aes.h"
#include "toolkit/sha256.h"

int main() {
  std::cout << "RSA TESTING" << std::endl;
  std::cout << "##########################################" << std::endl;

  std::string message = "RSA Encryption Test";
  RSAEncryption rsa(4096);
  std::cout << "Original Message: " << message << std::endl;
  
  std::string cipherText = rsa.encrypt(message);
  std::cout << "Ciphertext: " << cipherText << std::endl;

  std::string originalMessage = rsa.decrypt(cipherText);
  std::cout << "Decrypted Message: " << originalMessage << std::endl;

  std::cout << "##########################################" << std::endl;
  std::cout << std::endl;

  std::cout << "AES TESTING" << std::endl;
  std::cout << "##########################################" << std::endl;

  std::string key = "0123456789abcdef0123456789abcdef";
  std::string iv = "0123456789abcdef";
  AESEncryption aes(key, iv);
  message = "AES Encryption Test";
  std::cout << "Original Message: " << message << std::endl;

  cipherText = aes.encrypt(message);
  std::cout << "Ciphertext: " << cipherText << std::endl;

  originalMessage = aes.decrypt(cipherText);
  std::cout << "Decrypted Message: " << originalMessage << std::endl;

  std::cout << "##########################################" << std::endl;

  std::cout << std::endl;
  std::cout << "SHA-256 Hashing" << std::endl;
  std::cout << "##########################################" << std::endl;
  
  message = "SHA-256 Test";
  SHA256 sha256;

  std::string hash = sha256.hash(message);
  std::cout << "Original Message: " << message << std::endl;
  std::cout << "Hashed Message: " << hash << std::endl;
  std::cout << "##########################################" << std::endl;

  return 0;
}