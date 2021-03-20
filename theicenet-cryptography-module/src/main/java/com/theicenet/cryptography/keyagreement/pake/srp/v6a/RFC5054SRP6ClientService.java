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

import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.ByteArraysUtil.toBigInteger;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.ByteArraysUtil.toUnsignedByteArray;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ClientUtil.computeA;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ClientUtil.computeX;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.computeK;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.computeM2;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.computeU;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.generatePrivateValue;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.isValidPublicValue;

import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.keyagreement.SRP6ClientService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.math.BigInteger;
import org.apache.commons.lang.Validate;

/**
 * Implementation for SRP6 v6a `client` service according to Specification RFC 5054.
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
public class RFC5054SRP6ClientService implements SRP6ClientService {

  private final SRP6StandardGroup standardGroup;
  private final DigestService digestService;
  private final SecureRandomDataService secureRandomDataService;

  /**
   * @param standardGroup N,g standard group to use for this SRP6 RFC 5054 specification instance
   * @param digestAlgorithm hashing algorithm to use for this SRP6 RFC 5054 specification instance
   * @param secureRandomDataService service to generate secure random data
   */
  public RFC5054SRP6ClientService(
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
   * Generates a random SRP client's private value 'a' which is, according to the specification,
   * of at least 256 bits in length.
   *
   * Based on the generated client's private value 'a' it computes the client's public value 'A'
   * according to the standard routine:
   *
   *    A = (g^a) mod N
   *
   * @implNote This implementation ensures that the produced 'A' satisfies that
   *
   *    A mod N != 0
   *
   * as required by the API interface.
   */
  @Override
  public SRP6ClientValuesA computeValuesA() {
    BigInteger clientPrivateValueA;
    BigInteger clientPublicValueA;

    do {
      // Generate client's private value a
      clientPrivateValueA =
          generatePrivateValue(
              standardGroup.getN(),
              secureRandomDataService);

      // Generate client's public value A
      clientPublicValueA =
          computeA(
              standardGroup.getN(),
              standardGroup.getG(),
              clientPrivateValueA);
    } while (!isValidPublicValue(standardGroup.getN(), clientPublicValueA)); // loop till the client's public value A is valid

    return
        new SRP6ClientValuesA(
            toUnsignedByteArray(clientPrivateValueA),
            toUnsignedByteArray(clientPublicValueA));
  }

  /**
   * Computes the client's pre-master secret 'S' according to the standard routine:
   *
   *    S = ((B - (k * (g^x))) ^ (a + (u * x))) mod N
   */
  @Override
  public byte[] computeS(
      byte[] salt,
      byte[] identity,
      byte[] password,
      byte[] clientPrivateValueA,
      byte[] clientPublicValueA,
      byte[] serverPublicValueB) {

    Validate.notNull(salt);
    Validate.notNull(identity);
    Validate.notNull(password);
    Validate.notNull(clientPrivateValueA);
    Validate.notNull(clientPublicValueA);
    Validate.notNull(serverPublicValueB);

    final BigInteger k = computeK(digestService, standardGroup.getN(), standardGroup.getG());
    final BigInteger x = computeX(digestService, salt, identity, password);
    final BigInteger u =
        computeU(
            digestService,
            standardGroup.getN(),
            toBigInteger(clientPublicValueA),
            toBigInteger(serverPublicValueB));

    return
        toUnsignedByteArray(
            SRP6ClientUtil.computeS(
                standardGroup.getN(),
                standardGroup.getG(),
                k,
                x,
                u,
                toBigInteger(clientPrivateValueA),
                toBigInteger(serverPublicValueB)));
  }

  /**
   * Computes the client's evidence message 'M1' according to the standard routine:
   *
   *    M1 = H( A | B | S )
   */
  @Override
  public byte[] computeM1(byte[] clientPublicValueA, byte[] serverPublicValueB, byte[] s) {
    Validate.notNull(clientPublicValueA);
    Validate.notNull(serverPublicValueB);
    Validate.notNull(s);

    return
        toUnsignedByteArray(
            SRP6CommonUtil.computeM1(
                digestService,
                standardGroup.getN(),
                toBigInteger(clientPublicValueA),
                toBigInteger(serverPublicValueB),
                toBigInteger(s)));
  }

  /**
   * Computes the server's evidence message 'M2' according to the standard routine:
   *
   *    M2 = H( A | M1 | S )
   *
   * and compares the resulting value with what is passed in `receivedM2` to determine if the
   * received server's evidence message 'M2' is valid or not
   */
  @Override
  public boolean isValidReceivedM2(
      byte[] clientPublicValueA,
      byte[] s,
      byte[] m1,
      byte[] receivedM2) {

    Validate.notNull(clientPublicValueA);
    Validate.notNull(s);
    Validate.notNull(m1);
    Validate.notNull(receivedM2);

    final BigInteger m2 =
        computeM2(
            digestService,
            standardGroup.getN(),
            toBigInteger(clientPublicValueA),
            toBigInteger(m1),
            toBigInteger(s));

    return m2.equals(toBigInteger(receivedM2));
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
