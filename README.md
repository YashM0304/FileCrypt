# FileCrypt

The ‘filecrypt.py’ code provides authenticated, password-based file encryption and decryption. It combines PBKDF2, AES/3DES in CBC mode, and HMAC to ensure both confidentiality and integrity. All parameters required for decryption (cipher choice, hash, salt, IV, iteration count) are stored in a small JSON header at the start of the output file.
