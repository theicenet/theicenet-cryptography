package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2;

import com.theicenet.cryptography.provider.CryptographyProviderUtil;
import com.theicenet.cryptography.service.symmetric.pbkd.PBKDKeyService;
import com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2.exception.PBKDAlgorithmNotFoundException;
import com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2.exception.PBKDInvalidKeySpecException;
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

    final SecretKeyFactory secretKeyFactory =
        buildSecretKeyFactory(pbkdf2Configuration.getAlgorithm());

    final var pbeKeySpec =
        new PBEKeySpec(
            password.toCharArray(),
            salt,
            pbkdf2Configuration.getIterations(),
            keyLengthInBits);

    return generateKey(secretKeyFactory, pbeKeySpec);
  }

  private SecretKeyFactory buildSecretKeyFactory(String algorithm) {

    final SecretKeyFactory secretKeyFactory;
    try {
      secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new PBKDAlgorithmNotFoundException(algorithm, e);
    }

    return secretKeyFactory;
  }

  private SecretKey generateKey(SecretKeyFactory secretKeyFactory, PBEKeySpec pbeKeySpec) {
    try {
      return secretKeyFactory.generateSecret(pbeKeySpec);
    } catch (InvalidKeySpecException e) {
      throw new PBKDInvalidKeySpecException(e);
    }
  }
}
