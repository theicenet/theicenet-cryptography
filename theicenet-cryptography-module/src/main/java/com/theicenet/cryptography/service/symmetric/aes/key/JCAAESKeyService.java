package com.theicenet.cryptography.service.symmetric.aes.key;

import com.theicenet.cryptography.service.symmetric.aes.key.exception.AESKeyServiceException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JCAAESKeyService implements AESKeyService {

  private static final String AES = "AES";

  private final SecureRandom secureRandom;

  public JCAAESKeyService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public SecretKey generateKey(int keyLengthInBits) {
    KeyGenerator keyGenerator;
    try {
      keyGenerator = KeyGenerator.getInstance(AES);
    } catch (NoSuchAlgorithmException e) {
      throw new AESKeyServiceException("Key generation algorithm AES not found", e);
    }
    keyGenerator.init(keyLengthInBits, secureRandom);

    return keyGenerator.generateKey();
  }
}
