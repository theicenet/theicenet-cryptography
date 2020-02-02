package com.theicenet.cryptography.pbkd.pbkdf2;

import com.theicenet.cryptography.pbkd.PBKDKeyService;
import com.theicenet.cryptography.pbkd.PBKDKeyServiceException;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.lang.Validate;

public class JCAPBKDF2WithHmacSHAKeyService implements PBKDKeyService {

  private final PBKDF2Configuration pbkdf2Configuration;

  public JCAPBKDF2WithHmacSHAKeyService(PBKDF2Configuration pbkdf2Configuration) {
    this.pbkdf2Configuration = pbkdf2Configuration;

    // For PBKDF2WithHmacSHA3-XXX it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public SecretKey generateKey(String password, byte[] salt, int keyLengthInBits) {
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
      throw new PBKDKeyServiceException("Exception generating PBKDF2 key", e);
    }
  }

  private SecretKey generateKey(
      String algorithm,
      PBEKeySpec pbeKeySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {

    final var secretFactory = SecretKeyFactory.getInstance(algorithm);
    return secretFactory.generateSecret(pbeKeySpec);
  }
}
