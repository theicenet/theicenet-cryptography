package com.theicenet.cryptography.randomise.iv;

import com.theicenet.cryptography.randomise.RandomiseService;
import org.apache.commons.lang.Validate;

import java.security.SecureRandom;

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
