package com.theicenet.cryptography.service.asymmetric.rsa;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface RSACryptographyService {

  byte[] encrypt(PublicKey publicKey, byte[] clearContent);

  byte[] decrypt(PrivateKey privateKey, byte[] encryptedContent);
}
