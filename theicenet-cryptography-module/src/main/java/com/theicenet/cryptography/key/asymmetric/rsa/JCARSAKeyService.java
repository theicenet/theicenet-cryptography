package com.theicenet.cryptography.key.asymmetric.rsa;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyServiceException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.apache.commons.lang.Validate;

public class JCARSAKeyService implements AsymmetricKeyService {

  private static final String RSA = "RSA";

  private final SecureRandom secureRandom;

  public JCARSAKeyService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public KeyPair generateKey(int keyLengthInBits) {
    Validate.isTrue(keyLengthInBits > 0);

    KeyPairGenerator generator;
    try {
      generator = KeyPairGenerator.getInstance(RSA);
    } catch (NoSuchAlgorithmException e) {
      throw new AsymmetricKeyServiceException("Exception creating RSA key generator", e);
    }
    generator.initialize(keyLengthInBits, secureRandom);

    return generator.generateKeyPair();
  }
}
