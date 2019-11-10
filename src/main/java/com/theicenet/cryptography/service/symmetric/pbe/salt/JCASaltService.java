package com.theicenet.cryptography.service.symmetric.pbe.salt;

import java.security.SecureRandom;
import org.springframework.stereotype.Service;

@Service
public class JCASaltService implements SaltService {

  private final SecureRandom secureRandom;

  public JCASaltService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public byte[] generateRandom(int saltLengthInBytes) {
    final var salt = new byte[saltLengthInBytes];
    secureRandom.nextBytes(salt);

    return salt;
  }
}
