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
package com.theicenet.cryptography.cipher.symmetric.aes;

import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which encrypts and decrypts using AES
 * algorithm and an IV based block mode of operation.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">Advanced Encryption Standard (AES)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation">Block cipher mode of operation</a>
 * @see <a href="https://en.wikipedia.org/wiki/Initialization_vector">Initialization vector (IV)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCAAESIVCipherService extends JCAAESCipherBase implements SymmetricIVCipherService {

  private final BlockCipherIVModeOfOperation blockMode;

  public JCAAESIVCipherService(BlockCipherIVModeOfOperation blockMode) {
    Validate.notNull(blockMode);
    this.blockMode = blockMode;
  }

  @Override
  public byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent) {
    return process(
        Cipher.ENCRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        clearContent);
  }

  @Override
  public byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent) {
    return process(
        Cipher.DECRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        encryptedContent);
  }

  /**
   * @implNote Once this method returns the input and output streams have been closed as requested
   *           in the API interface.
   */
  @Override
  public void encrypt(
      SecretKey secretKey,
      byte[] iv,
      InputStream clearContentInputStream,
      OutputStream encryptedContentOutputStream) {

    process(
        Cipher.ENCRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        clearContentInputStream,
        encryptedContentOutputStream);
  }

  /**
   * @implNote Once this method returns the input and output streams have been closed as requested
   *           in the API interface.
   */
  @Override
  public void decrypt(
      SecretKey secretKey,
      byte[] iv,
      InputStream encryptedContentInputStream,
      OutputStream clearContentOutputStream) {

    process(
        Cipher.DECRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        encryptedContentInputStream,
        clearContentOutputStream);
  }
}
