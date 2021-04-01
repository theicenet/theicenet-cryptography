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
package com.theicenet.cryptography.keyagreement.pake.srp.v6a;

import static com.theicenet.cryptography.util.ByteArraysUtil.toUnsignedByteArray;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ClientUtil.computeX;

import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.keyagreement.SRP6VerifierService;
import org.apache.commons.lang.Validate;

/**
 * Implementation for SRP6 v6a `verifier` service according to Specification RFC 5054.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
 * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
 * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class RFC5054SRP6VerifierService implements SRP6VerifierService {

  private final SRP6StandardGroup standardGroup;
  private final DigestService digestService;

  /**
   * @param standardGroup N,g standard group to use for this SRP6 RFC 5054 specification instance
   * @param digestAlgorithm hashing algorithm to use for this SRP6 RFC 5054 specification instance
   */
  public RFC5054SRP6VerifierService(SRP6StandardGroup standardGroup, DigestAlgorithm digestAlgorithm) {
    Validate.notNull(standardGroup);
    Validate.notNull(digestAlgorithm);

    this.standardGroup = standardGroup;
    this.digestService = new JCADigestService(digestAlgorithm);
  }

  /**
   * Creates a new SRP v6a `verifier` according to the Specification RFC 5054
   *
   *    verifier = (g^x) mod N
   *    x = H(salt | H ( identity | ":" | password) )
   */
  @Override
  public byte[] generateVerifier(byte[] salt, byte[] identity, byte[] password) {
    Validate.notNull(salt);
    Validate.notNull(identity);
    Validate.notNull(password);

    return
        toUnsignedByteArray(
            SRP6ClientUtil.generateVerifier(
              standardGroup.getN(),
              standardGroup.getG(),
              computeX(digestService, salt, identity, password)));
  }
}
