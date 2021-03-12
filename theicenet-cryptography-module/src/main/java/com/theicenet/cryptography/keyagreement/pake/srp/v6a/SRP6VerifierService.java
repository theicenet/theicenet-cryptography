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
 * A `SRP6VerifierService` instance is a component which implements the required to generate a
 * SRP6 v6a verifier
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
public interface SRP6VerifierService {

  /**
   * Generates the SRP v6a `verifier`
   *
   * @param salt random 'salt' common to client and server
   * @param identity client's 'identity'
   * @param password client's 'password'
   * @return The generated SRP6 v6a `verifier` as big-endian unsigned binary representation
   */
  byte[] generateVerifier(byte[] salt, byte[] identity, byte[] password);
}
