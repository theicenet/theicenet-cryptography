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
package com.theicenet.cryptography.cipher.symmetric.aes;

import static com.theicenet.cryptography.util.ByteArraysUtil.concat;
import static com.theicenet.cryptography.util.ByteArraysUtil.split;

import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherNonIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherServiceException;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVCipherService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;
import javax.crypto.SecretKey;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which makes easy to encrypt and decrypt
 * using AES algorithm, hiding the underlying complexities, and requiring only the <b>content</b>
 * to encrypt/decrypt and the <b>secret key</b>, regardless of the block mode of operation used.
 *
 * In case the implemented block mode of operation is IV based, then the implementation will
 * generate the IV on the fly and will prefix/read it to/from the output/input.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">Advanced Encryption Standard (AES)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation">Block cipher mode of operation</a>
 * @see <a href="https://en.wikipedia.org/wiki/Initialization_vector">Initialization vector (IV)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 * @implNote
 *    This components ensures, as required by the API interface that the IV (when required)
 *    prefixed/read by the 'encrypt' and 'decrypt' methods has identical size and structure,
 *    so the output of the 'encrypt' method can be passed with no alteration into the 'decrypt'
 *    method to produce the clear content (as long as the <b>secret key</b> used is the same).
 *
 * @author Juan Fidalgo
 * @since 1.2.0
 */
public class JCAAESCipherService implements SymmetricCipherService {

  private static final int IV_SIZE_16_BYTES = 16;

  private final BlockCipherModeOfOperation blockMode;
  private final SymmetricNonIVCipherService aesNonIVCipherService;
  private final SymmetricIVCipherService aesIVCipherService;
  private final SecureRandomDataService randomDataService;

  public JCAAESCipherService(
      BlockCipherNonIVModeOfOperation blockMode,
      SymmetricNonIVCipherService aesNonIVCipherService,
      SecureRandomDataService randomDataService) {

    Validate.notNull(blockMode);
    Validate.notNull(aesNonIVCipherService);
    Validate.notNull(randomDataService);

    this.blockMode = BlockCipherModeOfOperation.valueOf(blockMode.name());
    this.aesNonIVCipherService = aesNonIVCipherService;
    this.aesIVCipherService = null;
    this.randomDataService = randomDataService;
  }

  public JCAAESCipherService(
      BlockCipherIVModeOfOperation blockMode,
      SymmetricIVCipherService aesIVCipherService,
      SecureRandomDataService randomDataService) {

    Validate.notNull(blockMode);
    Validate.notNull(aesIVCipherService);
    Validate.notNull(randomDataService);

    this.blockMode = BlockCipherModeOfOperation.valueOf(blockMode.name());
    this.aesNonIVCipherService = null;
    this.aesIVCipherService = aesIVCipherService;
    this.randomDataService = randomDataService;
  }

  @Override
  public byte[] encrypt(SecretKey secretKey, byte[] clearContent) {
    Validate.notNull(secretKey);
    Validate.notNull(clearContent);

    if (isNonIVBlockMode(blockMode)) {
      return aesNonIVCipherService.encrypt(secretKey, clearContent);
    }

    final byte[] iv = randomDataService.generateSecureRandomData(IV_SIZE_16_BYTES);
    final byte[] encrypted =
        aesIVCipherService.encrypt(
            secretKey,
            iv,
            clearContent);

    return concat(iv, encrypted);
  }

  @Override
  public byte[] decrypt(SecretKey secretKey, byte[] encryptedContent) {
    Validate.notNull(secretKey);
    Validate.notNull(encryptedContent);

    if (isNonIVBlockMode(blockMode)) {
      return aesNonIVCipherService.decrypt(secretKey, encryptedContent);
    }

    final byte[][] ivAndEncrypted = split(encryptedContent, IV_SIZE_16_BYTES);
    final byte[] iv = ivAndEncrypted[0];
    final byte[] encrypted = ivAndEncrypted[1];

    return
        aesIVCipherService.decrypt(
            secretKey,
            iv,
            encrypted);
  }

  @Override
  public void encrypt(
      SecretKey secretKey,
      InputStream clearContentInputStream,
      OutputStream encryptedContentOutputStream) {

    Validate.notNull(secretKey);
    Validate.notNull(clearContentInputStream);
    Validate.notNull(encryptedContentOutputStream);

    if (isNonIVBlockMode(blockMode)) {
      aesNonIVCipherService.encrypt(
          secretKey,
          clearContentInputStream,
          encryptedContentOutputStream);

      return;
    }

    final byte[] iv = randomDataService.generateSecureRandomData(IV_SIZE_16_BYTES);
    try {
      encryptedContentOutputStream.write(iv);
    } catch (IOException e) {
      throw new SymmetricCipherServiceException("Exception prefixing IV to output stream", e);
    }

    aesIVCipherService.encrypt(
        secretKey,
        iv,
        clearContentInputStream,
        encryptedContentOutputStream);
  }

  @Override
  public void decrypt(
      SecretKey secretKey,
      InputStream encryptedContentInputStream,
      OutputStream clearContentOutputStream) {

    Validate.notNull(secretKey);
    Validate.notNull(encryptedContentInputStream);
    Validate.notNull(clearContentOutputStream);

    if (isNonIVBlockMode(blockMode)) {
      aesNonIVCipherService.decrypt(
          secretKey,
          encryptedContentInputStream,
          clearContentOutputStream);

      return;
    }

    final byte[] iv;
    try {
      iv = encryptedContentInputStream.readNBytes(IV_SIZE_16_BYTES);
    } catch (IOException e) {
      throw new SymmetricCipherServiceException("Exception reading IV from output stream", e);
    }

    aesIVCipherService.decrypt(
        secretKey,
        iv,
        encryptedContentInputStream,
        clearContentOutputStream);
  }

  private boolean isNonIVBlockMode(BlockCipherModeOfOperation blockMode) {
    return Objects.equals(blockMode, BlockCipherModeOfOperation.ECB);
  }
}
