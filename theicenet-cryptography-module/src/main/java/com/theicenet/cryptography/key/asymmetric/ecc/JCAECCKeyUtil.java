/*
 * Copyright 2019-2020 the original author or authors.
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

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyServiceException;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public final class JCAECCKeyUtil {

  private static final String CURVE_LENGTH_PLACE_HOLDER = "XXX";

  static {
    // Bouncy Castle is required for most of the ECC curves
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  private JCAECCKeyUtil() {
  }

  public static KeyPair generateKey(
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
