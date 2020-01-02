package com.theicenet.cryptography.cipher.symmetric;

import javax.crypto.SecretKey;

public interface SymmetricRandomisedCipherService {

  byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent);

  byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent);
}
