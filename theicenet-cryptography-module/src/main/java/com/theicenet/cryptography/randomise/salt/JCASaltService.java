package com.theicenet.cryptography.randomise.salt;

import com.theicenet.cryptography.randomise.RandomiseService;
import java.security.SecureRandom;
import org.apache.commons.lang.Validate;

public class JCASaltService implements RandomiseService {

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
