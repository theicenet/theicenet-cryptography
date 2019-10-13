package com.theicenet.cryptography.service.symmetric.aes.key;

import com.theicenet.cryptography.service.symmetric.aes.key.exception.KeyGenerationAlgorithmNotFoundException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class JCAAESKeyService implements AESKeyService {

  private static final String AES = "AES";

  @Override
  public SecretKey generateAESKey(int keyLengthInBits) {
    KeyGenerator keyGenerator;
    try {
      keyGenerator = KeyGenerator.getInstance(AES);
    } catch (NoSuchAlgorithmException e) {
      throw new KeyGenerationAlgorithmNotFoundException(AES, e);
    }

    return keyGenerator.generateKey();
  }
}
