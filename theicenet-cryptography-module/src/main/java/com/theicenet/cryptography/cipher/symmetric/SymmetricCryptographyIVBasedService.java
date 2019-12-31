package com.theicenet.cryptography.cipher.symmetric;

import javax.crypto.SecretKey;

public interface SymmetricCryptographyIVBasedService {

  byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent);

  byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent);
}
