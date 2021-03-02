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
package com.theicenet.cryptography.cipher.symmetric;

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;

/**
 * A SymmetricNonIVCipherService instance is a component which encrypts and decrypts content
 * using a <b>secret key cryptography</b> (symmetric cryptography) algorithm with a block cipher
 * and a mode of operation which doesn't require an initialisation vector (IV).
 *
 * @see <a href="https://en.wikipedia.org/wiki/Symmetric-key_algorithm">Symmetric-key algorithm</a>
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher">Block cipher</a>
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation">Block cipher mode of operation</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface SymmetricNonIVCipherService {

  /**
   * Encrypts what is passed in <b>clearContent</b> using the secret key <b>secretKey</b>.
   *
   * @param secretKey secret key to use to encrypt the passed <b>clearContent</b>
   * @param clearContent clear content to encrypt using <b>secretKey</b>
   * @return result of encrypting <b>clearContent</b> with the <b>secretKey</b>
   *         by using a <b>secret key cryptography</b> algorithm
   */
  byte[] encrypt(SecretKey secretKey, byte[] clearContent);

  /**
   * Decrypts what is passed in <b>encryptedContent</b> using the secret key <b>privateKey</b>.
   *
   * @param secretKey secret key to use to decrypt the passed <b>encryptedContent</b>
   * @param encryptedContent encrypted content to decrypt using <b>secretKey</b>
   * @return the clear content, which is the result of decrypting <b>encryptedContent</b>
   *         with the <b>secretKey</b> by using a <b>secret key cryptography</b> algorithm
   */
  byte[] decrypt(SecretKey secretKey, byte[] encryptedContent);

  /**
   * Encrypts what is passed in <b>clearContentInputStream</b> using the secret key <b>secretKey</b>
   * and sends the encrypted result to <b>encryptedContentOutputStream</b>.
   *
   * @apiNote Once this method returns the input and output streams must have been closed
   *          so they can't be mutated.
   *
   * @param secretKey secretKey secret key to use to encrypt the input <b>clearContentInputStream</b>
   * @param clearContentInputStream input stream with clear content to encrypt using <b>secretKey</b>
   * @param encryptedContentOutputStream output stream where is sent the result of encrypting
   *                                     <b>clearContentInputStream</b> with the <b>secretKey</b>
   *                                     by using a <b>secret key cryptography</b> algorithm
   */
  void encrypt(
      SecretKey secretKey,
      InputStream clearContentInputStream,
      OutputStream encryptedContentOutputStream);

  /**
   * Decrypts what is passed in <b>encryptedContentInputStream</b> using the
   * secret key <b>secretKey</b> and sends the decrypted result to <b>clearContentOutputStream</b>.
   *
   * @apiNote Once this method returns the input and output streams must have been closed
   *          so they can't be mutated.
   *
   * @param secretKey secret key to use to decrypt the input <b>encryptedContentInputStream</b>
   * @param encryptedContentInputStream input stream with encrypted content to decrypt using
   *                                    <b>secretKey</b>
   * @param clearContentOutputStream output stream where is sent the result of decrypting
   *                                 <b>encryptedContentInputStream</b> with the <b>secretKey</b>
   *                                 by using a <b>secret key cryptography</b> algorithm
   */
  void decrypt(
      SecretKey secretKey,
      InputStream encryptedContentInputStream,
      OutputStream clearContentOutputStream);
}
