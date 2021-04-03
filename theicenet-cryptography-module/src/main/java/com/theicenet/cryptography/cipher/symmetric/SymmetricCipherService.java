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
 * A SymmetricCipherService instance is an easy to use component which encrypts and decrypts content
 * using a <b>secret key cryptography</b> (symmetric cryptography) algorithm.
 *
 * SymmetricCipherService hides any underlying complexity and only requires the <b>content</b>
 * to encrypt/decrypt and the <b>secret key</b>, regardless of the block mode of operation used.
 * In case the implemented block mode of operation is IV based, then the implementation will
 * generate the IV on the fly and will prefix/read it to/from the output/input.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Symmetric-key_algorithm">Symmetric-key algorithm</a>
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher">Block cipher</a>
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation">Block cipher mode of operation</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 * @apiNote
 *    The 'encrypt' and 'decrypt' methods will ensure that the IV (when required)
 *    prefixed/read has identical size and structure, so the output of the 'encrypt' method
 *    can be passed with no alteration into the 'decrypt' method to produce the clear content
 *    (as long as the <b>secret key</b> used is the same)
 *
 * @author Juan Fidalgo
 * @since 1.2.0
 */
public interface SymmetricCipherService {

  /**
   * Encrypts what is passed in <b>clearContent</b> using the secret key <b>secretKey</b>.
   *
   * If IV is required for the implemented block of operation, then, it will be generated on the fly
   * and prefixed to the output, so the prefix of the output will be the IV, and the remaining
   * will be the encrypted result.
   *
   * @param secretKey secret key to use to encrypt the passed <b>clearContent</b>
   * @param clearContent clear content to encrypt using <b>secretKey</b>
   * @return result of encrypting <b>clearContent</b> with the <b>secretKey</b>
   *         by using a <b>secret key cryptography</b> algorithm.
   *         If IV is required then it will be generated on the fly and prefixed to the output.
   */
  byte[] encrypt(SecretKey secretKey, byte[] clearContent);

  /**
   * Decrypts what is passed in <b>encryptedContent</b> using the secret key <b>privateKey</b>.
   *
   * If IV is required for the implemented block of operation, then, it will be prefixed in
   * the input, so the prefix of the input must be the IV, and the remaining
   * will be the encrypted content to decrypt.
   *
   * @param secretKey secret key to use to decrypt the passed <b>encryptedContent</b>
   * @param encryptedContent
   *    Encrypted content to decrypt using <b>secretKey</b>.
   *    For IV based block modes of operation the IV will be the prefix of <b>encryptedContent</b>,
   *    and the remaining will be the encrypted content to decrypt
   * @return the clear content, which is the result of decrypting <b>encryptedContent</b>
   *         with the <b>secretKey</b> by using a <b>secret key cryptography</b> algorithm
   */
  byte[] decrypt(SecretKey secretKey, byte[] encryptedContent);

  /**
   * Encrypts what is passed in <b>clearContentInputStream</b> using the secret key <b>secretKey</b>
   * and sends the encrypted result to <b>encryptedContentOutputStream</b>.
   *
   * If IV is required for the implemented block of operation, then, it will be generated on the fly
   * and prefixed to the output, so the prefix of the output will be the IV, and the remaining
   * will be the encrypted result.
   *
   * @apiNote Once this method returns the input and output streams must have been closed
   *          so they can't be mutated.
   *
   * @param secretKey secretKey secret key to use to encrypt the input <b>clearContentInputStream</b>
   * @param clearContentInputStream input stream with clear content to encrypt using <b>secretKey</b>
   * @param encryptedContentOutputStream
   *    Output stream where is sent the result of encrypting <b>clearContentInputStream</b> with
   *    the <b>secretKey</b> by using a <b>secret key cryptography</b> algorithm.
   *    If IV is required then it will be generated on the fly and prefixed to the output.
   */
  void encrypt(
      SecretKey secretKey,
      InputStream clearContentInputStream,
      OutputStream encryptedContentOutputStream);

  /**
   * Decrypts what is passed in <b>encryptedContentInputStream</b> using the
   * secret key <b>secretKey</b> and sends the decrypted result to <b>clearContentOutputStream</b>.
   *
   * If IV is required for the implemented block of operation, then, it will be prefixed in
   * the input, so the prefix of the input must be the IV, and the remaining
   * will be the encrypted content to decrypt.
   *
   * @apiNote Once this method returns the input and output streams must have been closed
   *          so they can't be mutated.
   *
   * @param secretKey secret key to use to decrypt the input <b>encryptedContentInputStream</b>
   * @param encryptedContentInputStream
   *    Input stream with encrypted content to decrypt using <b>secretKey</b>
   *    For IV based block modes of operation the IV will be the prefix of
   *    <b>encryptedContentInputStream</b>, and the remaining will be the encrypted
   *    content to decrypt
   * @param clearContentOutputStream
   *    Output stream where is sent the result of decrypting <b>encryptedContentInputStream</b>
   *    with the <b>secretKey</b> by using a <b>secret key cryptography</b> algorithm.
   */
  void decrypt(
      SecretKey secretKey,
      InputStream encryptedContentInputStream,
      OutputStream clearContentOutputStream);
}
