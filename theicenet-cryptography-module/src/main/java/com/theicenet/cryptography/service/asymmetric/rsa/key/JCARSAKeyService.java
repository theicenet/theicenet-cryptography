package com.theicenet.cryptography.service.asymmetric.rsa.key;

import com.theicenet.cryptography.service.asymmetric.rsa.key.exception.RSAKeyServiceException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JCARSAKeyService implements RSAKeyService {

  private static final String RSA = "RSA";

  private final SecureRandom secureRandom;

  public JCARSAKeyService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public KeyPair generateKey(int keyLengthInBits) {
    KeyPairGenerator generator;
    try {
      generator = KeyPairGenerator.getInstance(RSA);
    } catch (NoSuchAlgorithmException e) {
      throw new RSAKeyServiceException("Exception generating RSA key", e);
    }
    generator.initialize(keyLengthInBits, secureRandom);

    return generator.generateKeyPair();
  }
}
