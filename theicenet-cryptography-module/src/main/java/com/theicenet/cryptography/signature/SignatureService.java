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
package com.theicenet.cryptography.signature;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A SignatureService instance is a component which implements a mechanism to work with
 * <b>public key cryptography</b> (asymmetric cryptography) <b>digital signature</b>.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Digital_signature">Digital signature</a>
 * @see <a href="https://en.wikipedia.org/wiki/Public-key_cryptography">Public-key cryptography</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface SignatureService {

  /**
   * Calculates the signature of <b>content</b> using <b>privateKey</b>.
   *
   * @param privateKey private key to use to produce <b>signature</b> of <b>content</b>
   * @param content content to produce <b>signature</b> with <b>privateKey</b>
   * @return signature which is the result of signing <b>content</b> with the <b>privateKey</b>
   */
  byte[] sign(PrivateKey privateKey, byte[] content);

  /**
   * Verifies if <b>signature</b> is a valid signature for <b>content</b> produced signing
   * <b>content</b> with the private key pair of <b>publicKey</b>.
   *
   * @param publicKey public key which is the pair of the private key which was used to
   *                  sign <b>content</b> to produce <b>signature</b>
   * @param content content to verify that <b>signature</b> is a valid a signature produced signing
   *                <b>content</b> with the private key pair of <b>publicKey</b>
   * @param signature signature to verify that it's a valid signature for <b>content</b> produced
   *                  signing <b>content</b> with the private key pair of <b>publicKey</b>
   * @return true if <b>signature</b> is a valid signature of <b>content</b> when signing using
   *         private key pair of <b>publicKey</b>. false otherwise.
   */
  boolean verify(PublicKey publicKey, byte[] content, byte[] signature);

  /**
   * Calculates the signature of <b>contentInputStream</b> using <b>privateKey</b>.
   *
   * @apiNote Once this method returns the input stream must have been closed so it can't be mutated.
   *
   * @param privateKey private key to use to produce <b>signature</b> of <b>contentInputStream</b>
   * @param contentInputStream input stream with content to produce <b>signature</b>
   *                           with <b>privateKey</b>
   * @return signature which is the result of signing <b>contentInputStream</b> with the
   *         <b>privateKey</b>
   */
  byte[] sign(PrivateKey privateKey, InputStream contentInputStream);

  /**
   * Verifies if <b>signature</b> is a valid signature for <b>contentInputStream</b> produced
   * signing <b>contentInputStream</b> with the private key pair of <b>publicKey</b>.
   *
   * @apiNote Once this method returns the input stream must have been closed so it can't be mutated.
   *
   * @param publicKey public key which is the pair of the private key which was used to
   *                  sign <b>contentInputStream</b> to produce <b>signature</b>
   * @param contentInputStream input stream with content to verify that <b>signature</b> is a valid
   *                           signature produced signing <b>contentInputStream</b> with the private
   *                           key pair of <b>publicKey</b>
   * @param signature signature to verify that it's a valid signature for <b>contentInputStream</b>
   *                  produced signing <b>contentInputStream</b> with the private key pair of
   *                  <b>publicKey</b>
   * @return true if <b>signature</b> is a valid signature of <b>contentInputStream</b> when signing
   *         using private key pair of <b>publicKey</b>. false otherwise.
   */
  boolean verify(PublicKey publicKey, InputStream contentInputStream, byte[] signature);
}
