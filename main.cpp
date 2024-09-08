#include <iostream>
#include <fstream>
#include <string>
#include "toolkit/rsa.h"
#include "toolkit/aes.h"
#include "toolkit/sha256.h"

int main() {
  std::cout << "WELCOME - Cryptography Toolkit" << std::endl;
  std::cout << "------------------------------------------------------------" << std::endl;

  std::string filename;
  std::cout << "What would you like to name your output file?" << std::endl;
  std::getline(std::cin, filename);
  std::cout << "Creating file " << filename << ".txt" << std::endl;
  std::ofstream outFile(filename + ".txt", std::ios::app);

  while(true) {
    std::cout << "Please select your tool: \'RSA\', \'AES\', \'SHA-256\'" << std::endl;
    RSAEncryption* rsaPtr = nullptr;
    AESEncryption* aesPtr = nullptr;
    SHA256* shaPtr = nullptr;
    std::string tool;
    std::getline(std::cin, tool);

    if(tool == "RSA") {
      std::cout << "Please enter key size (2048 or 4096)" << std::endl;
      int keySize;
      while(true) {
        std::cin >> keySize;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if(keySize != 2048 && keySize != 4096) {
          std::cout << "Please enter a valid key size" << std::endl;
          continue;
        } else {
          break;
        }
      }

      rsaPtr = new RSAEncryption(keySize);
      std::string message;
      std::cout << "Please enter the message to be encrypted" << std::endl;
      std::getline(std::cin, message);
      outFile << "Encrypting: " << message << std::endl;
      outFile << "------------------------------------------------------" << std::endl;

      std::string encrypted = rsaPtr->encrypt(message);
      outFile << encrypted << std::endl;

      char decrypt;
      std::cout << "Would you like to decrypt the encryption? (y/n)" << std::endl;
      std::cin >> decrypt;
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

      if(decrypt == 'y') {
        std::string message = rsaPtr->decrypt(encrypted);
        outFile << std::endl;
        outFile << "Decrypted Ciphertext: " << message << std::endl;
        outFile << "------------------------------------------------------" << std::endl;
        outFile << std::endl;
        outFile << std::endl << "RSA DONE" << std::endl;
        outFile << "######################################################" << std::endl;
        outFile << std::endl;
      } else {
        delete rsaPtr;
      }
    } else if(tool == "AES") {
      aesPtr = new AESEncryption();
      std::string message;
      std::cout << "Please enter the message to be encrypted" << std::endl;
      std::getline(std::cin, message);
      outFile << "Encrypting: " << message << std::endl;
      outFile << "------------------------------------------------------" << std::endl;

      std::string encrypted = aesPtr->encrypt(message);
      outFile << encrypted << std::endl;

      char decrypt;
      std::cout << "Would you like to decrypt the encryption? (y/n)" << std::endl;
      std::cin >> decrypt;
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

      if(decrypt == 'y') {
        std::string message = aesPtr->decrypt(encrypted);
        outFile << std::endl;
        outFile << "Decrypted Ciphertext: " << message << std::endl;
        outFile << "------------------------------------------------------" << std::endl;
        outFile << std::endl;
        outFile << std::endl << "AES DONE" << std::endl;
        outFile << "######################################################" << std::endl;
        outFile << std::endl;
      } else {
        delete aesPtr;
      }
    } else if(tool == "SHA-256") {
      shaPtr = new SHA256();
      std::string message;
      std::cout << "Please enter the message to be hashed" << std::endl;
      std::getline(std::cin, message);
      outFile << "Hashing: " << message << std::endl;
      outFile << "------------------------------------------------------" << std::endl;

      std::string hashed = shaPtr->hash(message);
      outFile << hashed << std::endl;

      delete shaPtr;
      outFile << std::endl << "SHA DONE" << std::endl;
      outFile << "######################################################" << std::endl;
      outFile << std::endl;
    } else {
      std::cout << "Please ensure tool is entered exactly as prompted, without the quotes" << std::endl;
      continue;
    }

    std::cout << "Continue? (y/n)" << std::endl;
    while(true) {
      char cont;
      std::cin >> cont;
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

      if(cont != 'y' && cont != 'n') {
        std::cout << "Please enter \'y\' to continue, or \'n\' to quit." << std::endl;
        continue;
      } else if(cont == 'n') {
        outFile.close();
        return 0;
      } else {
        break;
      }
    }
  }
}