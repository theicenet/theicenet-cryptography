package com.theicenet.cryptography.pbkd;

import java.util.Base64;
import javax.crypto.SecretKey;

public interface PBKDKeyService {
  SecretKey generateKey(String password, byte[] salt, int keyLengthInBits);

  default SecretKey generateKey(byte[] secret, byte[] salt, int keyLengthInBits) {
    return generateKey(
        new String(Base64.getEncoder().encode(secret)),
        salt,
        keyLengthInBits);
  }
}
