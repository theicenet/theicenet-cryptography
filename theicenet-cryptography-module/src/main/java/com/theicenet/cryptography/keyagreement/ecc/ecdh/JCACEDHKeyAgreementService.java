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
package com.theicenet.cryptography.keyagreement.ecc.ecdh;

import com.theicenet.cryptography.key.asymmetric.ecc.ECCKeyAlgorithm;
import com.theicenet.cryptography.keyagreement.KeyAgreementService;
import com.theicenet.cryptography.keyagreement.KeyAgreementServiceException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which implements Elliptic-curve
 * Diffie–Hellman key exchange.
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Elliptic-curve_Diffie-Hellman">Elliptic-curve Diffie–Hellman</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCACEDHKeyAgreementService implements KeyAgreementService {

  private static final ECCKeyAlgorithm ECDH = ECCKeyAlgorithm.ECDH;

  @Override
  public byte[] generateSecretKey(PrivateKey privateKey, PublicKey publicKey) {
    Validate.notNull(privateKey);
    Validate.notNull(publicKey);

    KeyAgreement keyAgreement;
    try {
      keyAgreement = KeyAgreement.getInstance(ECDH.toString());
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(publicKey, true);
    } catch (Exception e) {
      throw new KeyAgreementServiceException(
          "Error generating key agreement component for algorithm ECDH",
          e);
    }

    return keyAgreement.generateSecret();
  }
}
