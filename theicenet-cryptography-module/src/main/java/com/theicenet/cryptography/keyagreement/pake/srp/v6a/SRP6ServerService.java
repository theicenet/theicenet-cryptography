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

/**
 * A SRP6ServerService instance is a component which implements the required to support
 * the server end to verify a client's sign in using SRP6 v6a protocol
 *
 * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
 * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
 * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public interface SRP6ServerService {

  /**
   * Generates a random SRP server's private value 'b' which is, according to the specification,
   * of at least 256 bits in length
   *
   * Based on the generated server's private value 'b' it's computed the server's public value 'B'
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @apiNote Any implementation of this method <b>must</b> ensure that the produced 'B'
   * satisfies that
   *
   *    B mod N != 0
   *
   * @param verifier password verifier 'v'
   * @return The computed server's private value 'b' and server's public value 'B'
   */
  SRP6ServerValuesB computeValuesB(byte[] verifier);

  /**
   * Computes the server's pre-master secret 'S'
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param verifier password verifier 'v'
   * @param clientPublicValueA client's public value 'A'
   * @param serverPrivateValueB server's private value 'a'
   * @param serverPublicValueB server's public value 'B'
   * @return The computed server's pre-master key 'S' as big-endian unsigned binary representation
   */
  byte[] computeS(
      byte[] verifier,
      byte[] clientPublicValueA,
      byte[] serverPrivateValueB,
      byte[] serverPublicValueB);

  /**
   * Checks if the received client's evidence message 'M1' is valid
   *
   * @param clientPublicValueA client's public value 'A'
   * @param serverPublicValueB server's public value 'B'
   * @param s server's pre-master secret 'S'
   * @param receivedM1 received client's evidence message 'M1'
   * @return true if received client's evidence message 'M1' is valid. Other case false
   */
  boolean isValidReceivedM1(
      byte[] clientPublicValueA,
      byte[] serverPublicValueB,
      byte[] s,
      byte[] receivedM1);

  /**
   * Computes the server's evidence message 'M2'
   *
   * @param clientPublicValueA client's public value 'A'
   * @param s server's pre-master secret 'S'
   * @param receivedM1 received client's evidence message 'M1'
   * @return The computed server's evidence message 'M2' as big-endian unsigned binary representation
   */
  byte[] computeM2(
      byte[] clientPublicValueA,
      byte[] s,
      byte[] receivedM1);

  /**
   * Computes the common session 'Key'
   *
   * @param s server's pre-master secret 'S'
   * @return The computed common session 'key' as big-endian unsigned binary representation
   */
  byte[] computeSessionKey(byte[] s);
}
