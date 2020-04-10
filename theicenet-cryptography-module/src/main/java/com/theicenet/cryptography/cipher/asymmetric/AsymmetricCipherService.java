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
package com.theicenet.cryptography.cipher.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * An AsymmetricCipherService instance is a component which encrypts and decrypts content
 * using a <b>public key cryptography</b> (asymmetric cryptography) algorithm.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Public-key_cryptography">Public-key cryptography</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface AsymmetricCipherService {

  /**
   * Encrypts what is passed in <b>clearContent</b> using the public key <b>publicKey</b>.
   *
   * @param publicKey public key (format X.509) to use to encrypt the passed <b>clearContent</b>
   * @param clearContent clear content to encrypt using <b>publicKey</b>
   * @return result of encrypting <b>clearContent</b> with the <b>publicKey</b>
   *         by using a <b>public key cryptography</b> algorithm
   *
   * @see <a href="https://en.wikipedia.org/wiki/X.509">X.509</a>
   */
  byte[] encrypt(PublicKey publicKey, byte[] clearContent);

  /**
   * Decrypts what is passed in <b>encryptedContent</b> using the private key <b>privateKey</b>.
   *
   * @param privateKey private key (format PCKS #8) to use to decrypt the passed
   *                   <b>encryptedContent</b>
   * @param encryptedContent encrypted content to decrypt using <b>privateKey</b>
   * @return the clear content, which is the result of decrypting <b>encryptedContent</b>
   *         with the <b>privateKey</b> by using a <b>public key cryptography</b> algorithm
   *
   * @see <a href="https://en.wikipedia.org/wiki/PKCS_8">PKCS #8</a>
   */
  byte[] decrypt(PrivateKey privateKey, byte[] encryptedContent);
}
