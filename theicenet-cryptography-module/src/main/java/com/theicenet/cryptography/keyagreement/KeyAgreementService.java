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
package com.theicenet.cryptography.keyagreement;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A KeyAgreementService instance is a component which implements a cryptographic
 * unauthenticated key-agreement protocol for <b>two parties</b> agree on a secret shared key
 * in such a way that both influence the outcome.
 *
 * Instances of KeyAgreementService are valid to be used for unauthenticated
 * <b>securely exchanging cryptographic keys</b> over a public channel.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Key-agreement_protocol">Key-agreement protocol</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface KeyAgreementService {

  /**
   * Generates a common, repeatable and deterministic <b>secret shared key</b> which is influenced
   * by the <b>privateKey</b> and the <b>publicKey</b>.
   *
   * The generation of the shared secret involves two parties (Bod and Alice) and their key pairs.
   *
   * @param privateKey Bob's (or Alice) private key (format PCKS #8) to use to generate the
   *                   secret shared key
   * @param publicKey Alice's (or Bob) public key (format X.509) to use to generate the
   *                  secret shared key
   * @return generated common secret shared key which satisfies that,
   *         generateSecretKey(bobPrivateKey, alicePublicKey) is equals to
   *         generateSecretKey(alicePrivateKey, bobPublicKey)
   *
   * @see <a href="https://en.wikipedia.org/wiki/X.509">X.509</a>
   * @see <a href="https://en.wikipedia.org/wiki/PKCS_8">PKCS #8</a>
   */
  byte[] generateSecretKey(PrivateKey privateKey, PublicKey publicKey);
}
