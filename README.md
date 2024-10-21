# RKENC - Ragekill-Encrypt

**RKENC** is a lightweight AES encryption library. (It supports **C.T.O** aswell [Compile-Time-Obfuscation])
* It only requires cryptopp library.
* Supports multiple data types.
- string, int, bool, double, float, long, etc. are supported.
- Made for c++20

# Platform:
* Cross-Platform. (macOS, Windows, Linux)
* If you intend to port it *elsewhere*, for example, IOS, you'd need to build cryptopp for IOS.

## Features

- **AES Encryption** -> Cryptopp
- **Type Support** -> supports multiple data types.
- **Lightweight** -> single header, which is easy to understand.
- **Anti-Debug** -> Anti-Debugging built in for cross-platform.
- **C.T.O(Compile-Time-Obfuscation)** -> Using XOR for compile time obfuscation.
P.S: I added C.T.O on a whim, it's probably not the best thing you could use for obfuscation. It would only deter skids and noobies. I'd recommend to remove it, and just use [O-LLVM](https://github.com/obfuscator-llvm/obfuscator), which is an llvm obfuscator for clang.

## Prequisites:

To use RKENC, you need to have the Crypto++ library installed. You can install it on **Ubuntu** using:

```bash
sudo apt-get install libcrypto++-dev
```

For **Arch-Linux**:
```bash
sudo pacman -S cryptopp
```
You will also need a cpp compiler that supports **c++20**, like **g++** or **clang**. Both can be used. I use clang.

# Example usage:

```cpp
#include "rkenc.h"

int main() {
    RKENC::AESCRYPT rk;

    
    int normalInt = 42;
    std::string crypt = rk.encrypt(normalInt);
    std::cout << "Encrypted: " << crypt << std::endl;

    
    int decrypted = rk.decrypt<int>(crypt);
    std::cout << "Decrypted: " << crypt << std::endl;

    return 0;
}
```
# Output:
Encrypted: G"��v��#B>��P��������9�~Z��t��]�{E�._


Decrypted: 42

# Anti-Debugging (NEW):-
**Output**:-
```bash
Starting program: /home/rage/RKENC/aes_encryptor 
Downloading separate debug info for system-supplied DSO at 0x7ffff7fc5000
Downloading separate debug info for /usr/lib/libcryptopp.so.8                      
warning: `/home/rage/.cache/debuginfod_client/98b3d8e0b8c534c769cb871c438b4f8f3a8e4bf3/debuginfo': can't read symbols: file format not recognized.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
[Inferior 1 (process 300089) exited with code 01] ---> Our anti-debug detects the debugger (gdb in this case), and terminates the program.
```

# Compiling:
```bash
clang++ -std=c++20 main.cpp -o aes_encryptor -lcryptopp
```

# Updates:
~Soon. If there are any requests to update it, I will respond.~
* Added **anti-debugging** mechanism for cross-platform
* Added **C.T.O**

# License:
- * You are free to use this code and modify it to your liking. I am not responsible for any damage caused by it.
- * Do not use this code for malicious purposes. 
