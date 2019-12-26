package com.theicenet.cryptography.service.asymmetric.rsa;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface RSACryptographyService {

    byte[] encrypt(Padding padding, PublicKey publicKey, byte[] clearContent);

    byte[] decrypt(Padding padding, PrivateKey privateKey, byte[] encryptedContent);
}
