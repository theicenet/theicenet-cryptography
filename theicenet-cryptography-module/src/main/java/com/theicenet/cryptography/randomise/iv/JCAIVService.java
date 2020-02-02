package com.theicenet.cryptography.randomise.iv;

import com.theicenet.cryptography.randomise.RandomiseService;
import java.security.SecureRandom;
import org.apache.commons.lang.Validate;

public class JCAIVService implements RandomiseService {

  private final SecureRandom secureRandom;

  public JCAIVService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public byte[] generateRandom(int ivLengthInBytes) {
    Validate.isTrue(ivLengthInBytes > 0);

    final byte[] iv = new byte[ivLengthInBytes];
    secureRandom.nextBytes(iv);

    return iv;
  }
}
