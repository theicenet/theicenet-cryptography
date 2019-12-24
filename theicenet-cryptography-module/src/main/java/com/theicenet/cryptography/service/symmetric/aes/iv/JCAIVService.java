package com.theicenet.cryptography.service.symmetric.aes.iv;

import java.security.SecureRandom;

public class JCAIVService implements IVService {

  private final SecureRandom secureRandom;

  public JCAIVService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public byte[] generateRandom(int ivLengthInBytes) {
    final byte[] iv = new byte[ivLengthInBytes];
    secureRandom.nextBytes(iv);

    return iv;
  }
}
