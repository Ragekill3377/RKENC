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
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>

#define AES_CBC 0 // disabled
#define AES_GCM 1 // enabled

namespace RKENC {

void erase(unsigned char* data, size_t length) {
    std::fill(data, data + length, 0);
}

class AESCRYPT {
public:
    AESCRYPT() {
        CryptoPP::AutoSeededRandomPool prng;

        prng.GenerateBlock(key, sizeof(key));
        ivgen();
    }

    void ivgen() {
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(iv, sizeof(iv));
    }

    template<typename T>
    std::string to_string(const T& data) {
        std::ostringstream oss;
        if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>) {
            oss << data; // << support for basic types
        } else {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
            for (size_t i = 0; i < sizeof(T); ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
            }
        }
        return oss.str();
    }

    template<typename T>
    T from_string(const std::string& str) {
        T data;
        if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>) {
            std::istringstream iss(str);
            iss >> data;
        } else {
            unsigned char* bytes = reinterpret_cast<unsigned char*>(&data);
            for (size_t i = 0; i < sizeof(T); ++i) {
                std::string byteString = str.substr(i * 2, 2);
                bytes[i] = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
            }
        }
        return data;
    }

    // Encrypt
    template<typename T>
    std::string encrypt(const T& data) {
        std::string plaintext = to_string(data);
        std::string ciphertext;

#if AES_CBC == 1
        CryptoPP::AES::Encryption aesEncryption(key, sizeof(key));
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(key, sizeof(key), iv);
        CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
        stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
        stfEncryptor.MessageEnd();
#endif

#if AES_GCM == 1
        CryptoPP::GCM<CryptoPP::AES>::Encryption gcmEncryption;
        gcmEncryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        CryptoPP::AuthenticatedEncryptionFilter aef(gcmEncryption, new CryptoPP::StringSink(ciphertext));
        aef.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
        aef.MessageEnd();
#endif

        return ciphertext;
    }

    // Decrypt
    template<typename T>
    T decrypt(const std::string& ciphertext) {
        std::string decryptedtext;

#if AES_CBC == 1
        CryptoPP::AES::Decryption aesDecryption(key, sizeof(key));
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbcDecryption(key, sizeof(key), iv);
        CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
        stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
        stfDecryptor.MessageEnd();
#endif

#if AES_GCM == 1
        CryptoPP::GCM<CryptoPP::AES>::Decryption gcmDecryption;
        gcmDecryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        CryptoPP::AuthenticatedDecryptionFilter adf(gcmDecryption, new CryptoPP::StringSink(decryptedtext));
        adf.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
        adf.MessageEnd();
#endif

        return from_string<T>(decryptedtext);
    }

    
    ~AESCRYPT() {
        erase(key, sizeof(key));
        erase(iv, sizeof(iv));   
    }

private:
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]; // AES key
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];          // IV
};

}
