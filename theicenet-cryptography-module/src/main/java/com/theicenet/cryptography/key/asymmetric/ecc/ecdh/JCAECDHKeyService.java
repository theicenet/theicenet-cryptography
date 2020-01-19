package com.theicenet.cryptography.key.asymmetric.ecc.ecdh;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.ecc.ECCCurve;
import com.theicenet.cryptography.key.asymmetric.ecc.ECCKeyAlgorithm;
import com.theicenet.cryptography.key.asymmetric.ecc.JCAECCKeyUtil;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.KeyPair;
import java.security.SecureRandom;
import org.apache.commons.lang.Validate;

public class JCAECDHKeyService implements AsymmetricKeyService {

  private static final ECCKeyAlgorithm ECDH = ECCKeyAlgorithm.ECDH;

  private final ECCCurve curve;
  private final SecureRandom secureRandom;

  public JCAECDHKeyService(ECCCurve curve, SecureRandom secureRandom) {
    Validate.notNull(curve);
    Validate.notNull(secureRandom);

    this.curve = curve;
    this.secureRandom = secureRandom;

    // Bouncy Castle is required for most of the ECC curves
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public KeyPair generateKey(int keyLengthInBits) {
    return JCAECCKeyUtil.generateKey(keyLengthInBits, curve, ECDH, secureRandom);
  }
}
