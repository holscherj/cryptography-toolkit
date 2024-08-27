#include <iostream>
#include <string>
#include "toolkit/rsa.h"

int main() {
  std::string message = "RSA Encryption Test";
  RSAEncryption* rsa = new RSAEncryption(4096);
  std::cout << "Original Message: " << message << std::endl;
  
  std::string cipherText = rsa->encrypt(message);
  std::cout << "Ciphertext: " << cipherText << std::endl;

  std::string originalMessage = rsa->decrypt(cipherText);
  std::cout << "Decrypted Message: " << originalMessage << std::endl;
  return 0;
}