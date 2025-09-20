# PureHybridCrypto

**PureHybridCrypto** is a Python-based hybrid encryption library providing secure, multi-layer encryption for both text and files. It combines XOR-based encryption, shuffling, salting, and a double-layer system with integrity verification to ensure robust data protection.

---
#Requirments

```python
python>=3.6
```

## Features

- **Text Encryption/Decryption**
  - Multi-round shuffling with a key-based pattern.
  - XOR-based encryption with optional salt for added randomness.
  - Base64 encoding for safe storage and transfer.
  
- **File Encryption/Decryption**
  - Encrypt any file into a secure package with salt and metadata.
  - Decrypt packages back into the original file.
  
- **Randomized Configuration**
  - Automatic generation of random keys, number of rounds, and salt length.
  
- **Double-Layer Encryption**
  - Adds a secondary static key layer for integrity verification.
  - Detects tampering via SHA-256-based integrity hash.
  
- **CLI Demo**
  - Interactive console demo for text and file encryption.

---

## Installation

Clone this repository:

```bash
git clone https://github.com/akshsaraf/Encryption-Decryption.git
cd Encryption-Decryption
```

Functions Overview
Function	Description
encrypt(text)                             Encrypts a string with multiple rounds, shuffle, and XOR.
decrypt(encrypted_text)	                  Decrypts the encrypted string.
encrypt_file(input_path, output_path)	    Encrypts a file and stores it as JSON with salt.
decrypt_file(input_path, output_path)	    Decrypts a file encrypted via encrypt_file.
encrypt_with_config(text)	                Encrypts text with randomized key/rounds/salt.
decrypt_with_config(bundle_json)	        Decrypts a bundle created by encrypt_with_config.
encrypt_with_double_layer(text)	          Double-layer encryption with integrity hash.
decrypt_with_double_layer(encrypted_text)	Decrypts double-layer encrypted text, verifying integrity.

Security Notes:-

  The library uses symmetric encryption; the same key is used for encryption and decryption.

  Random salts and shuffling patterns improve security but are not a replacement for standard encryption libraries in high-       security environments.

  Double-layer encryption adds tamper detection via a static integrity key.

  
