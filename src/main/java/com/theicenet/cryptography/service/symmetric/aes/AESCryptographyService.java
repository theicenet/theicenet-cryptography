package com.theicenet.cryptography.service.symmetric.aes;

import javax.crypto.SecretKey;

public interface AESCryptographyService {

  byte[] encrypt(
      BlockCipherModeOfOperation mode,
      SecretKey secretKey,
      byte[] iv,
      byte[] message);
}
