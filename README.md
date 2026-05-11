# FileCrypt

FileCrypt is a command-line Python tool for password-based file encryption and decryption. It provides authenticated encryption by combining symmetric encryption with HMAC-based integrity verification.

The tool supports AES-128, AES-256, and 3DES encryption in CBC mode. It derives encryption and HMAC keys from a user-provided password using PBKDF2 and stores the required decryption parameters in a small JSON header inside the encrypted output file.

## Features

- Password-based file encryption and decryption
- Supports AES-128, AES-256, and 3DES
- Supports SHA-256 and SHA-512 for PBKDF2 and HMAC
- Uses PBKDF2 for key derivation
- Uses HMAC to detect tampering or incorrect passwords
- Stores encryption metadata such as cipher, hash, salt, IV, and iteration count in the encrypted file header
- Simple command-line interface

## Repository Structure

```text
FileCrypt/
│
├── filecrypt.py        # Main encryption and decryption script
├── sampletext.txt      # Sample plaintext file
├── encryptedtext       # Example encrypted output file
├── decryptedtext       # Example decrypted output file
└── README.md           # Project documentation
