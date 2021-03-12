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

import com.theicenet.cryptography.cipher.symmetric.BlockCipherNonIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherServiceException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which encrypts and decrypts using AES
 * algorithm and a non IV based block mode of operation.
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
public class JCAAESNonIVCipherService implements SymmetricNonIVCipherService {

  private final BlockCipherNonIVModeOfOperation blockMode;

  public JCAAESNonIVCipherService(
      BlockCipherNonIVModeOfOperation blockMode) {
    Validate.notNull(blockMode);
    this.blockMode = blockMode;
  }

  @Override
  public byte[] encrypt(SecretKey secretKey, byte[] clearContent) {
    return process(
        Cipher.ENCRYPT_MODE,
        secretKey,
        clearContent);
  }

  @Override
  public byte[] decrypt(SecretKey secretKey, byte[] encryptedContent) {
    return process(Cipher.DECRYPT_MODE, secretKey, encryptedContent);
  }

  /**
   * @implNote Once this method returns the input and output streams have been closed as requested
   *           in the API interface.
   */
  @Override
  public void encrypt(
      SecretKey secretKey,
      InputStream clearContentInputStream,
      OutputStream encryptedContentOutputStream) {

    process(
        Cipher.ENCRYPT_MODE,
        secretKey,
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
      InputStream encryptedContentInputStream,
      OutputStream clearContentOutputStream) {
    
    process(
        Cipher.DECRYPT_MODE,
        secretKey,
        encryptedContentInputStream,
        clearContentOutputStream);
  }

  private byte[] process(int operationMode, SecretKey secretKey, byte[] content) {
    Validate.notNull(secretKey);
    Validate.notNull(content);

    final Cipher cipher = createCipher(operationMode, secretKey);

    try {
      return cipher.doFinal(content);
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception processing AES content", e);
    }
  }

  private void process(
      int operationMode,
      SecretKey secretKey,
      InputStream inputStream,
      OutputStream outputStream) {

    Validate.notNull(secretKey);
    Validate.notNull(inputStream);
    Validate.notNull(outputStream);

    final Cipher cipher = createCipher(operationMode, secretKey);
    final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);

    try (inputStream; cipherOutputStream; outputStream) {
      inputStream.transferTo(cipherOutputStream);
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception processing AES content", e);
    }
  }

  private Cipher createCipher(Integer operationMode, SecretKey secretKey) {

    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(String.format("AES/%s/PKCS5PADDING", blockMode));
      cipher.init(operationMode, secretKey);
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception creating AES cipher", e);
    }

    return cipher;
  }
}
