package com.theicenet.cryptography.key.asymmetric.dsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.apache.commons.lang.Validate;

public class JCADSAKeyService implements DSAKeyService {

  private static final String DSA = "DSA";

  private final SecureRandom secureRandom;

  public JCADSAKeyService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public KeyPair generateKey(int keyLengthInBits) {
    Validate.isTrue(keyLengthInBits > 0);

    KeyPairGenerator generator;
    try {
      generator = KeyPairGenerator.getInstance(DSA);
    } catch (NoSuchAlgorithmException e) {
      throw new DSAKeyServiceException("Exception generating DSA key", e);
    }
    generator.initialize(keyLengthInBits, secureRandom);

    return generator.generateKeyPair();
  }
}
