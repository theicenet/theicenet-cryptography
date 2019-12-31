package com.theicenet.cryptography.cipher.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface AsymmetricCryptographyService {

  byte[] encrypt(PublicKey publicKey, byte[] clearContent);

  byte[] decrypt(PrivateKey privateKey, byte[] encryptedContent);
}
