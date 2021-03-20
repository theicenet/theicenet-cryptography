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
package com.theicenet.cryptography.keyagreement;

import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ClientValuesA;

/**
 * A SRP6ClientService instance is a component which implements the required to support
 * the client end to sign in using SRP6 v6a protocol
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
public interface SRP6ClientService {

  /**
   * Generates a random SRP client's private value 'a' which is, according to the specification,
   * of at least 256 bits in length
   *
   * Based on the generated client's private value 'a' it's computed the client's public value 'A'
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @apiNote Any implementation of this method <b>must</b> ensure that the produced 'A'
   * satisfies that
   *
   *    A mod N != 0
   *
   * @return The computed client's private value 'a' and client's public value 'A'
   */
  SRP6ClientValuesA computeValuesA();

  /**
   * Computes the client's pre-master secret 'S'
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param salt random 'salt' common to client and server
   * @param identity client's 'identity'
   * @param password client's 'password'
   * @param clientPrivateValueA client's private value 'a'
   * @param clientPublicValueA client's public value 'A'
   * @param serverPublicValueB server's public value 'B'
   * @return The computed client's pre-master key 'S' as big-endian unsigned binary representation
   */
  byte[] computeS(
      byte[] salt,
      byte[] identity,
      byte[] password,
      byte[] clientPrivateValueA,
      byte[] clientPublicValueA,
      byte[] serverPublicValueB);

  /**
   * Computes the client's evidence message 'M1'
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param clientPublicValueA client's private value 'a'
   * @param serverPublicValueB server's public value 'B'
   * @param s client's pre-master secret 'S'
   * @return The computed client's evidence message 'M1' as big-endian unsigned binary representation
   */
  byte[] computeM1(
      byte[] clientPublicValueA,
      byte[] serverPublicValueB,
      byte[] s);

  /**
   * Checks if the received server's evidence message 'M2' is valid
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param clientPublicValueA client's public value 'A'
   * @param s client's pre-master secret 'S'
   * @param m1 client's evidence message 'M1'
   * @param receivedM2 received server's evidence message 'M2'
   * @return true if received server's evidence message 'M2' is valid. Other case false
   */
  boolean isValidReceivedM2(
      byte[] clientPublicValueA,
      byte[] s,
      byte[] m1,
      byte[] receivedM2);

  /**
   * Computes the common session 'Key'
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param s client's pre-master secret 'S'
   * @return The computed common session 'key' as big-endian unsigned binary representation
   */
  byte[] computeSessionKey(byte[] s);
}
