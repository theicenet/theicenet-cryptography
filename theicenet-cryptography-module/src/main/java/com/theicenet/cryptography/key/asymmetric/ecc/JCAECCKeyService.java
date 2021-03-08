/*
 * Copyright 2019-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.theicenet.cryptography.key.asymmetric.ecc;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyServiceException;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class JCAECCKeyService implements AsymmetricKeyService {

  private static final String CURVE_LENGTH_PLACE_HOLDER = "XXX";

  private final ECCKeyAlgorithm algorithm;
  private final ECCCurve curve;
  private final SecureRandom secureRandom;

  public JCAECCKeyService(ECCKeyAlgorithm algorithm, ECCCurve curve, SecureRandom secureRandom) {
    Validate.notNull(algorithm);
    Validate.notNull(curve);
    Validate.notNull(secureRandom);

    this.algorithm = algorithm;
    this.curve = curve;
    this.secureRandom = secureRandom;

    // Bouncy Castle is required for most of the ECC curves
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  /**
   * @implNote Generated private key is <b>PKCS #8</b> format as required by the API interface.
   * @implNote Generate public key is <b>X.509</b> format as required by the API interface.
   */
  @Override
  public KeyPair generateKey(int keyLengthInBits) {
    return generateKey(keyLengthInBits, curve, algorithm, secureRandom);
  }

  private KeyPair generateKey(
      int keyLengthInBits,
      ECCCurve curve,
      ECCKeyAlgorithm eccKeyAlgorithm,
      SecureRandom secureRandom) {

    Validate.isTrue(
        curve.getKeyLengths().contains(keyLengthInBits),
        String.format(
            "Invalid keyLength[%s] for ECC curve %s. Supported key lengths for this curve are %s",
            keyLengthInBits,
            curve,
            curve.getKeyLengths()));
    Validate.notNull(curve);
    Validate.notNull(eccKeyAlgorithm);
    Validate.notNull(secureRandom);

    KeyPairGenerator generator;
    try {
      generator = KeyPairGenerator.getInstance(eccKeyAlgorithm.toString());
      generator.initialize(
          new ECGenParameterSpec(
              curve.toString().replace(CURVE_LENGTH_PLACE_HOLDER, String.valueOf(keyLengthInBits))),
          secureRandom);
    } catch (Exception e) {
      throw new AsymmetricKeyServiceException(
          String.format("Exception creating %s key generator", eccKeyAlgorithm),
          e);
    }

    return generator.generateKeyPair();
  }
}
