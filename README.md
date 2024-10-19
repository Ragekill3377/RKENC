# RKENC - Ragekill-Encrypt

**RKENC** is a lightweight AES encryption library.
* It only requires cryptopp library.
* Supports multiple data types.
- string, int, bool, double, float, long, etc. are supported.

# Platform:
* Cross-Platform. (macOS, Windows, Linux)
* If you intend to port it *elsewhere*, for example, IOS, you'd need to build cryptopp for IOS.

## Features

- **AES Encryption** -> Cryptopp
- **Multiple Encryption rounds** -> loop for encryption. default is 3. Encrypts thrice, decrypts thrice.
- **Type Support** -> supports multiple data types.
- **Lightweight** -> single header, which is less than 100 lines long, and easy to understand.

## Prequisites:

To use RKENC, you need to have the Crypto++ library installed. You can install it on **Ubuntu** using:

```bash
sudo apt-get install libcryptopp-dev
```

For **Arch-Linux**:
```bash
sudo pacman -S cryptopp
```
You will also need a cpp compiler, like **g++** or **clang**. Both can be used. I use clang.

# Example usage:

```cpp
#include "rkenc.h"

int main() {
    RKENC::AESCRYPT aes;

    
    int normalInt = 42;
    std::string crypt = aes.encrypt(normalInt);
    std::cout << "Encrypted: " << crypt << std::endl;

    
    int decrypted = aes.decrypt<int>(crypt);
    std::cout << "Decrypted: " << crypt << std::endl;

    return 0;
}
```
# Output:
Encrypted: G"��v��#B>��P������
                              ��9�~Z��t��]�{E�._
Decrypted: 42


# Compiling:
```bash
clang++ main.cpp -o aes_encryptor -lcryptopp
```

* You are free to use this code and modify it to your liking. I am not responsible for any damage caused by it.

# Updates:
* Soon. If there are any requests to update it, I will respond.
