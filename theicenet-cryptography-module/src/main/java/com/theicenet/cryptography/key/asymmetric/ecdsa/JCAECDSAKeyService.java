package com.theicenet.cryptography.key.asymmetric.ecdsa;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.apache.commons.lang.Validate;

public class JCAECDSAKeyService implements AsymmetricKeyService {

  private static final String ECDSA = "ECDSA";
  private static final String BC = "BC";

  private static final String CURVE_LENGTH_PLACE_HOLDER = "XXX";

  private final ECDSACurve curve;
  private final SecureRandom secureRandom;

  public JCAECDSAKeyService(ECDSACurve curve, SecureRandom secureRandom) {
    this.curve = curve;
    this.secureRandom = secureRandom;

    // All ECC cryptography is delegated to BC implementation
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public KeyPair generateKey(int keyLengthInBits) {
    Validate.isTrue(
        curve.getKeyLengths().contains(keyLengthInBits),
        String.format(
            "Invalid keyLength[%s] for ECDSA curve %s. Supported key lengths for the curve are %s",
            keyLengthInBits,
            curve,
            curve.getKeyLengths()));

    KeyPairGenerator generator;
    try {
      // There is intrinsic complexity on properly implementing ECC cryptography on any given curve
      // without leaking secret information. For all ECC cryptography we want to be sure that
      // the security provider used is the Bouncy Castle one.
      generator = KeyPairGenerator.getInstance(ECDSA, BC);
      generator.initialize(
          new ECGenParameterSpec(
              curve.toString().replace(CURVE_LENGTH_PLACE_HOLDER, String.valueOf(keyLengthInBits))),
          secureRandom);
    } catch (Exception e) {
      throw new ECDSAKeyServiceException("Exception creating ECDSA BC key generator", e);
    }

    return generator.generateKeyPair();
  }
}
