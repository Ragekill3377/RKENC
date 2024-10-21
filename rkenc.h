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


#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#elif defined(__linux__)
    #include <sys/ptrace.h>
    #include <unistd.h>
#elif defined(__APPLE__)
    #include <sys/types.h>
    #include <sys/ptrace.h>
#endif

namespace RKENC {

/* Anti-Debug */
void dbg_disable() {
#if defined(_WIN32) || defined(_WIN64)
    if (IsDebuggerPresent()) { // built-in func for windows. 'debugapi.h' header to be precise.
        exit(1);               // If you want to check (for windows), that if a remote process is being debugged, use 'CheckRemoteDebuggerPresent' function. 
    }
#elif defined(__linux__) || defined(__APPLE__)
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) { // for unix based systems, you'll have to look for ptrace like this.
        exit(1);
    }
#endif
} // If debugger is present, crash. Very simple implementation, and this can be easily bypassed. Nothing is fool-proof.

/* BEGIN C.T.O */
// To be honest, This is probably the most useless component. 'Compile-Time-Obfuscation' is usally...shit.
// You could remove this if you want, along with the obfuscate & deobfuscate calls.
// The actual 'meat' of the program is the encryption.
// This obfuscation is only going to deter skids and noobies. You could leave it here for them! (jk)

constexpr unsigned int seed = 99999; // set this to whatever you want.

constexpr unsigned int xorshift(unsigned int x) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}


constexpr unsigned char genxorkey() {
    return static_cast<unsigned char>(xorshift(seed) & 0xFF);
}

// Obfuscate each char
constexpr void obfuscate_char(char* ptr, size_t index, unsigned char key) {
    *ptr = *ptr ^ (key + index);
}

constexpr std::string obfuscate(const std::string& data) {
    unsigned char key = genxorkey();
    std::string obfuscated(data);

    for (size_t i = 0; i < obfuscated.length(); ++i) {
        char* ptr = &obfuscated[i];
        obfuscate_char(ptr, i, key);
    }

    return obfuscated;
}

constexpr void deobfuscate_char(char* ptr, size_t index, unsigned char key) {
    *ptr = *ptr ^ (key + index); 
}

constexpr std::string deobfuscate(const std::string& data) {
    unsigned char key = genxorkey();
    std::string deobfuscated(data);

    for (size_t i = 0; i < deobfuscated.length(); ++i) {
        char* ptr = &deobfuscated[i];
        deobfuscate_char(ptr, i, key);
    }

    return deobfuscated;
}

/* END C.T.O */

class AESCRYPT {
public:
    AESCRYPT() {
        
        dbg_disable();

        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(key, sizeof(key)); // auto gen key & iv
        prng.GenerateBlock(iv, sizeof(iv));
    }
    // these 2 funcs, to_string and from_string will allow us to work with multiple built-in data types. :)
    template<typename T>
    std::string to_string(const T& data) {
        std::ostringstream oss;
        oss << data;
        return oss.str();
    }

    template<typename T>
    T from_string(const std::string& str) {
        std::istringstream iss(str);
        T data;
        iss >> data;
        return data;
    }
    // main components.
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

        return obfuscate(ciphertext);
    }

    template<typename T>
    T decrypt(const std::string& obfuscated_ciphertext) {
        std::string ciphertext = deobfuscate(obfuscated_ciphertext);

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
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]; // AES key
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];          // IV
};

}
