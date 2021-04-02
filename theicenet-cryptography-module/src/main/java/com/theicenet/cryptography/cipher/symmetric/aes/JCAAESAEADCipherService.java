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

import com.theicenet.cryptography.cipher.symmetric.BlockCipherAEADModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricAEADCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which encrypts and decrypts using AES
 * algorithm and an IV based block mode of operation which supports Authenticated Encryption
 * with Associated Data (AEAD)..
 *
 * @see <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">Advanced Encryption Standard (AES)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation">Block cipher mode of operation</a>
 * @see <a href="https://en.wikipedia.org/wiki/Initialization_vector">Initialization vector (IV)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Authenticated_encryption">Authenticated Encryption with Associated Data (AEAD)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCAAESAEADCipherService extends JCAAESCipherBase implements SymmetricAEADCipherService {

  private final BlockCipherAEADModeOfOperation blockMode;

  public JCAAESAEADCipherService(BlockCipherAEADModeOfOperation blockMode) {
    Validate.notNull(blockMode);
    this.blockMode = blockMode;
  }

  @Override
  public byte[] encrypt(
      SecretKey secretKey,
      byte[] iv,
      byte[] clearContent,
      byte[]... associatedData) {

    return process(
        Cipher.ENCRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        clearContent,
        associatedData);
  }

  @Override
  public byte[] decrypt(
      SecretKey secretKey,
      byte[] iv,
      byte[] encryptedContent,
      byte[]... associatedData) {

    return process(
        Cipher.DECRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        encryptedContent,
        associatedData);
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
      OutputStream encryptedContentOutputStream,
      byte[]... associatedData) {

    process(
        Cipher.ENCRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        clearContentInputStream,
        encryptedContentOutputStream,
        associatedData);
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
      OutputStream clearContentOutputStream,
      byte[]... associatedData) {

    process(
        Cipher.DECRYPT_MODE,
        BlockCipherModeOfOperation.valueOf(blockMode.name()),
        secretKey,
        iv,
        encryptedContentInputStream,
        clearContentOutputStream,
        associatedData);
  }
}
