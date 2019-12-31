package com.theicenet.cryptography.service.symmetric.aes;

import javax.crypto.SecretKey;

public interface AESCryptographyService {

  byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent);

  byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent);
}
