package com.theicenet.cryptography.cipher.symmetric.aes;

import javax.crypto.SecretKey;

public interface AESCryptographyService {

  byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent);

  byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent);
}
