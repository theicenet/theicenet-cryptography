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
package com.theicenet.cryptography.key.asymmetric.ecc.ecdsa;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.ecc.ECCCurve;
import com.theicenet.cryptography.key.asymmetric.ecc.ECCKeyAlgorithm;
import com.theicenet.cryptography.key.asymmetric.ecc.JCAECCKeyUtil;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.KeyPair;
import java.security.SecureRandom;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which generates ECDSA key pairs.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">Elliptic Curve Digital Signature Algorithm</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCAECDSAKeyService implements AsymmetricKeyService {

  private static final ECCKeyAlgorithm ECDSA = ECCKeyAlgorithm.ECDSA;

  private final ECCCurve curve;
  private final SecureRandom secureRandom;

  public JCAECDSAKeyService(ECCCurve curve, SecureRandom secureRandom) {
    Validate.notNull(curve);
    Validate.notNull(secureRandom);

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
    return JCAECCKeyUtil.generateKey(keyLengthInBits, curve, ECDSA, secureRandom);
  }
}
