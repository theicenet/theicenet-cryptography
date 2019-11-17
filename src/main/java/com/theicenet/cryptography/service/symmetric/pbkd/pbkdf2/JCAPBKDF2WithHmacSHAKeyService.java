package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2;

import com.theicenet.cryptography.provider.CryptographyProviderUtil;
import com.theicenet.cryptography.service.symmetric.pbkd.PBKDKeyService;
import com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2.exception.JCAPBKDF2WithHmacSHAKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.lang.Validate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JCAPBKDF2WithHmacSHAKeyService implements PBKDKeyService {

  private final String PBKDF2_WITH_HMAC = "PBKDF2WithHmac";

  private final PBKDF2Configuration pbkdf2Configuration;

  public JCAPBKDF2WithHmacSHAKeyService(
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.shaAlgorithm}") ShaAlgorithm shaAlgorithm,
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.iterations}") Integer iterations) {

    this.pbkdf2Configuration =
        new PBKDF2Configuration(
            String.format("%s%s", PBKDF2_WITH_HMAC, shaAlgorithm.toString()),
            iterations);

    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public SecretKey deriveKey(String password, byte[] salt, int keyLengthInBits) {
    Validate.notNull(password);
    Validate.notNull(salt);
    Validate.isTrue(keyLengthInBits > 0);

    try {
      final var pbeKeySpec =
          new PBEKeySpec(
              password.toCharArray(),
              salt,
              pbkdf2Configuration.getIterations(),
              keyLengthInBits);

      return generateKey(pbkdf2Configuration.getAlgorithm(), pbeKeySpec);
    } catch (Exception e) {
      throw new JCAPBKDF2WithHmacSHAKeyException(e);
    }
  }

  private SecretKey generateKey(
      String algorithm,
      PBEKeySpec pbeKeySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {

    final var secretFactory = SecretKeyFactory.getInstance(algorithm);
    return secretFactory.generateSecret(pbeKeySpec);
  }
}
