package com.theicenet.cryptography.service.symmetric.aes.key;

import com.theicenet.cryptography.service.symmetric.aes.key.exception.KeyGenerationAlgorithmNotFoundException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
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
      throw new KeyGenerationAlgorithmNotFoundException(AES, e);
    }
    keyGenerator.init(keyLengthInBits, secureRandom);

    return keyGenerator.generateKey();
  }
}
