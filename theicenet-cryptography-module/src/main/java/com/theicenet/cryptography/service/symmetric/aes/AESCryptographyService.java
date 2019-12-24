package com.theicenet.cryptography.service.symmetric.aes;

import javax.crypto.SecretKey;

public interface AESCryptographyService {

  byte[] encrypt(
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] clearContent);

  byte[] decrypt(
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] encryptedContent);
}
