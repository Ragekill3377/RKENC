#pragma once
/* Ragekill-Encrypt */
/* Crypto++         */

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <type_traits>

namespace RKENC {

class AESCRYPT {
public:
    AESCRYPT() {
        CryptoPP::AutoSeededRandomPool prng;

        prng.GenerateBlock(key, sizeof(key)); // auto gen key & iv
        prng.GenerateBlock(iv, sizeof(iv));
    }

    
    template<typename T>
    std::string to_string(const T& data) {
        if constexpr (std::is_arithmetic_v<T>) {
            return std::to_string(data);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return data;
        } else {
            static_assert(!std::is_same_v<T, T>, "Unsupported type");
        }
    }

    
    template<typename T>
    T from_string(const std::string& str) {
        if constexpr (std::is_arithmetic_v<T>) {
            std::istringstream iss(str);
            T data;
            iss >> data;
            return data;
        } else if constexpr (std::is_same_v<T, std::string>) {
            return str;
        } else {
            static_assert(!std::is_same_v<T, T>, "Unsupported type");
        }
    }

    // encrypt
    template<typename T>
    std::string encrypt(const T& data) {
        std::string plaintext = to_string(data);
        std::string ciphertext = plaintext;

        CryptoPP::AES::Encryption aesEncryption(key, sizeof(key));
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(reinterpret_cast<const CryptoPP::byte*>(key), sizeof(key), iv);

        std::string temp;
        CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(temp));
        stfEncryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length());
        stfEncryptor.MessageEnd();
        ciphertext = temp;

        return ciphertext;
    }

    // decrypt
    template<typename T>
    T decrypt(const std::string& ciphertext) {
        std::string decryptedtext = ciphertext;

        CryptoPP::AES::Decryption aesDecryption(key, sizeof(key));
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbcDecryption(reinterpret_cast<const CryptoPP::byte*>(key), sizeof(key), iv);

        std::string temp;
        CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(temp));
        stfDecryptor.Put(reinterpret_cast<const unsigned char*>(decryptedtext.c_str()), decryptedtext.size());
        stfDecryptor.MessageEnd();
        decryptedtext = temp;

        return from_string<T>(decryptedtext);
    }

private:
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]; // aes key
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];          // iv
};

}
