package com.theicenet.cryptography.key.symmetric.aes;

import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import org.apache.commons.lang.Validate;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JCAAESKeyService implements SymmetricKeyService {

  private static final String AES = "AES";

  private final SecureRandom secureRandom;

  public JCAAESKeyService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  @Override
  public SecretKey generateKey(int keyLengthInBits) {
    Validate.isTrue(keyLengthInBits > 0);

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
