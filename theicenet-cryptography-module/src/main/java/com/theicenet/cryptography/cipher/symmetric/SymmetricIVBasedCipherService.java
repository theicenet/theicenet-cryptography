package com.theicenet.cryptography.cipher.symmetric;

import javax.crypto.SecretKey;

public interface SymmetricIVBasedCipherService {

  byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent);

  byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent);
}
