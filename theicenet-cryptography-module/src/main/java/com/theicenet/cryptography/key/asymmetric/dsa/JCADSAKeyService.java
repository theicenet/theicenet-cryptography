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
package com.theicenet.cryptography.key.asymmetric.dsa;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyServiceException;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.lang3.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which generates DSA key pairs.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Digital_Signature_Algorithm">Digital Signature Algorithm</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCADSAKeyService implements AsymmetricKeyService {

  private static final String DSA = "DSA";

  private final SecureRandomDataService secureRandomDataService; // We store the whole SecureRandomDataService, although we are interested only in the embedded SecureRandom provider. The embedded SecureRandom might be recycled over the time following SecureRandomDataService's prediction protection rules

  public JCADSAKeyService(SecureRandomDataService secureRandomDataService) {
    Validate.notNull(secureRandomDataService);
    this.secureRandomDataService = secureRandomDataService;
  }

  /**
   * @implNote Generated private key is <b>PKCS #8</b> format as required by the API interface.
   * @implNote Generate public key is <b>X.509</b> format as required by the API interface.
   */
  @Override
  public KeyPair generateKey(int keyLengthInBits) {
    Validate.isTrue(keyLengthInBits > 0);

    KeyPairGenerator generator;
    try {
      generator = KeyPairGenerator.getInstance(DSA);
    } catch (NoSuchAlgorithmException e) {
      throw new AsymmetricKeyServiceException("Exception generating DSA key", e);
    }
    generator.initialize(keyLengthInBits, secureRandomDataService.getSecureRandom());

    return generator.generateKeyPair();
  }
}
