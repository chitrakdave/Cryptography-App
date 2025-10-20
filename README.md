🔐 **Cryptography-App**

This project demonstrates the implementation and performance analysis of various cryptographic algorithms — including AES, RSA, DSA, and Hashing — using Python’s PyCryptodome library.
It also includes a utility to generate dummy files of different sizes for encryption and hashing tests.

⚙️ **Features**

## 🔒 Features

### 🧩 AES Encryption/Decryption
- Supports **CBC** and **CTR** modes  
- Tests with **128-bit** and **256-bit** keys  

### 🔑 RSA Encryption/Decryption
- Uses **PKCS1_OAEP** padding  
- Key sizes: **2048-bit** and **3072-bit**  

### 🧮 Hashing Algorithms
- **SHA-256**  
- **SHA-512**  
- **SHA3-256**  

### 🖋️ DSA Digital Signatures
- Key sizes: **2048-bit** and **3072-bit**  
- Uses **DSS (Digital Signature Standard)** for signing and verification  

### ⚡ Performance Metrics
- Measures execution time *(in nanoseconds or microseconds)*  
- Calculates **speed per byte** for encryption, decryption, hashing, and signing  

## 🚀 How to Run

### 1. Install Dependencies
pip install pycryptodome

### 2. Generate Test Files
python createFiles.py

This will create:

smallFile.txt (1 KB)

largeFile_1MB.txt (1 MB)

largeFile.txt (10 MB)

### 3. Run Cryptographic Tests
python cryptotools.py

You’ll see detailed timing and speed results for all algorithms.

### 🧠 Concepts Covered

Symmetric key encryption (AES)

Asymmetric key encryption (RSA)

Hashing algorithms

Digital signatures using DSA

Performance benchmarking of cryptographic operations
