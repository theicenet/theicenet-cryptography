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

import static com.theicenet.cryptography.util.ByteArraysUtil.toBigInteger;
import static com.theicenet.cryptography.util.ByteArraysUtil.toUnsignedByteArray;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.computeK;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.computeM1;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.computeU;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.generatePrivateValue;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.isValidPublicValue;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ServerUtil.computeB;
import static com.theicenet.cryptography.util.SecureEqualUtil.areEqual;

import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.keyagreement.SRP6ServerService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.math.BigInteger;
import org.apache.commons.lang3.Validate;

/**
 * Implementation for SRP6 v6a 'server' service according to Specification RFC 5054.
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
public class RFC5054SRP6ServerService implements SRP6ServerService {

  private final SRP6StandardGroup standardGroup;
  private final DigestService digestService;
  private final SecureRandomDataService secureRandomDataService;

  /**
   * @param standardGroup N,g standard group to use for this SRP6 RFC 5054 specification instance
   * @param digestAlgorithm hashing algorithm to use for this SRP6 RFC 5054 specification instance
   * @param secureRandomDataService service to generate secure random data
   */
  public RFC5054SRP6ServerService(
      SRP6StandardGroup standardGroup,
      DigestAlgorithm digestAlgorithm,
      SecureRandomDataService secureRandomDataService) {

    Validate.notNull(standardGroup);
    Validate.notNull(digestAlgorithm);
    Validate.notNull(secureRandomDataService);

    this.standardGroup = standardGroup;
    this.digestService = new JCADigestService(digestAlgorithm);
    this.secureRandomDataService = secureRandomDataService;
  }

  /**
   * Generates a random SRP server's private value 'b' which is, according to the specification,
   * of at least 256 bits in length.
   *
   * Based on the generated server's private value 'b' and the 'verifier' it computes the
   * server's public value 'B' according to the standard routine:
   *
   *    B = ((k*v) + (g^b)) mod N
   *
   * @implNote This implementation ensures that the produced 'B' satisfies that
   *
   *    B mod N != 0
   *
   * as required by the API interface.
   */
  @Override
  public SRP6ServerValuesB computeValuesB(byte[] verifier) {
    Validate.notNull(verifier);

    final BigInteger k = computeK(digestService, standardGroup.getN(), standardGroup.getG());

    BigInteger serverPrivateValueB;
    BigInteger serverPublicValueB;

    do {
      // Generate server's private value b
      serverPrivateValueB =
          generatePrivateValue(
              standardGroup.getN(),
              secureRandomDataService);

      // Generate server's public value B
      serverPublicValueB =
          computeB(
              standardGroup.getN(),
              standardGroup.getG(),
              k,
              toBigInteger(verifier),
              serverPrivateValueB);
    } while (!isValidPublicValue(standardGroup.getN(), serverPublicValueB)); // loop till the server's public value B is valid

    return
        new SRP6ServerValuesB(
            toUnsignedByteArray(serverPrivateValueB),
            toUnsignedByteArray(serverPublicValueB));
  }

  /**
   * Computes the server's pre-master secret 'S' according to the standard routine:
   *
   *    S = ((A * ((v^u) mod N)) ^ b) mod N
   */
  @Override
  public byte[] computeS(
      byte[] verifier,
      byte[] clientPublicValueA,
      byte[] serverPrivateValueB,
      byte[] serverPublicValueB) {

    Validate.notNull(verifier);
    Validate.notNull(clientPublicValueA);
    Validate.notNull(serverPrivateValueB);
    Validate.notNull(serverPublicValueB);

    final BigInteger u =
        computeU(
            digestService,
            standardGroup.getN(),
            toBigInteger(clientPublicValueA),
            toBigInteger(serverPublicValueB));

    return
        toUnsignedByteArray(
            SRP6ServerUtil.computeS(
                standardGroup.getN(),
                toBigInteger(verifier),
                u,
                toBigInteger(serverPrivateValueB),
                toBigInteger(clientPublicValueA)));
  }

  /**
   * Computes the client's evidence message 'M1' according to the standard routine:
   *
   *    M1 = H( A | B | S )
   *
   * and compares the resulting value with what is passed in <b>receivedM1</b> to determine if the
   * received client's evidence message 'M1' is valid or not
   */
  @Override
  public boolean isValidReceivedM1(
      byte[] clientPublicValueA,
      byte[] serverPublicValueB,
      byte[] s,
      byte[] receivedM1) {

    Validate.notNull(clientPublicValueA);
    Validate.notNull(serverPublicValueB);
    Validate.notNull(s);
    Validate.notNull(receivedM1);

    final BigInteger m1 =
        computeM1(
            digestService,
            standardGroup.getN(),
            toBigInteger(clientPublicValueA),
            toBigInteger(serverPublicValueB),
            toBigInteger(s));

    return areEqual(toUnsignedByteArray(m1), receivedM1);
  }

  /**
   * Computes the server's evidence message 'M2' according to the standard routine:
   *
   *    M2 = H( A | M1 | S )
   */
  @Override
  public byte[] computeM2(
      byte[] clientPublicValueA,
      byte[] s,
      byte[] receivedM1) {

    Validate.notNull(clientPublicValueA);
    Validate.notNull(s);
    Validate.notNull(receivedM1);

    return
        toUnsignedByteArray(
            SRP6CommonUtil.computeM2(
                digestService,
                standardGroup.getN(),
                toBigInteger(clientPublicValueA),
                toBigInteger(receivedM1),
                toBigInteger(s)));
  }

  /**
   * Computes the common session 'Key' according to the standard routine:
   *
   *    Key = H(S)
   */
  @Override
  public byte[] computeSessionKey(byte[] s) {
    Validate.notNull(s);

    return
        toUnsignedByteArray(
            SRP6CommonUtil.computeSessionKey(
                digestService,
                standardGroup.getN(),
                toBigInteger(s)));
  }
}
