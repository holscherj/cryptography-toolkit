#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include "toolkit/rsa.h"
#include "toolkit/aes.h"
#include "toolkit/sha256.h"

void handleRSA(std::ofstream &outFile);
void handleAES(std::ofstream &outFile);
void handleSHA256(std::ofstream &outFile);
bool askContinue();

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
      handleRSA(outFile);
    } else if(tool == "AES") {
      handleAES(outFile);
    } else if(tool == "SHA-256") {
      handleSHA256(outFile);
    } else {
      std::cout << "Please ensure tool is entered exactly as prompted, without the quotes" << std::endl;
      continue;
    }

    if(!askContinue()) {
      outFile.close();
      return 0;
    }
  }
}

void handleRSA(std::ofstream& outFile) {
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

  std::unique_ptr<RSAEncryption> rsaPtr = std::make_unique<RSAEncryption>(keySize);
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
  }

  outFile << std::endl;
  outFile << std::endl << "RSA DONE" << std::endl;
  outFile << "######################################################" << std::endl;
  outFile << std::endl;
}

void handleAES(std::ofstream& outFile) {
  std::unique_ptr<AESEncryption> aesPtr = std::make_unique<AESEncryption>();
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
  }

  outFile << std::endl;
  outFile << std::endl << "AES DONE" << std::endl;
  outFile << "######################################################" << std::endl;
  outFile << std::endl;
}

void handleSHA256(std::ofstream& outFile) {
  std::unique_ptr<SHA256> shaPtr = std::make_unique<SHA256>();
  std::string message;
  std::cout << "Please enter the message to be hashed" << std::endl;
  std::getline(std::cin, message);
  
  outFile << "Hashing: " << message << std::endl;
  outFile << "------------------------------------------------------" << std::endl;
  std::string hashed = shaPtr->hash(message);
  outFile << hashed << std::endl;

  outFile << std::endl << "SHA DONE" << std::endl;
  outFile << "######################################################" << std::endl;
  outFile << std::endl;
}

bool askContinue() {
  std::cout << "Continue? (y/n)" << std::endl;
  while(true) {
    char cont;
    std::cin >> cont;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if(cont == 'y') {
      return true;
    } else if(cont == 'n') {
      return false;
    } else {
      std::cout << "Please enter 'y' to continue, or 'n' to quit." << std::endl;
    }
  }
}