package com.theicenet.cryptography.pbkd.salt;

import org.apache.commons.lang.Validate;

import java.security.SecureRandom;

public class JCASaltService implements SaltService {

  private final SecureRandom secureRandom;

  public JCASaltService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public byte[] generateRandom(int saltLengthInBytes) {
    Validate.isTrue(saltLengthInBytes > 0);

    final byte[] salt = new byte[saltLengthInBytes];
    secureRandom.nextBytes(salt);

    return salt;
  }
}
