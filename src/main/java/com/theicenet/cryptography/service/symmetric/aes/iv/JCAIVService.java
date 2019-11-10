package com.theicenet.cryptography.service.symmetric.aes.iv;

import java.security.SecureRandom;
import org.apache.commons.lang.Validate;
import org.springframework.stereotype.Service;

@Service
public class JCAIVService implements IVService {
  private final SecureRandom secureRandom;

  public JCAIVService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public byte[] generateRandom(int ivLengthInBytes) {
    final var iv = new byte[ivLengthInBytes];
    secureRandom.nextBytes(iv);

    return iv;
  }
}
