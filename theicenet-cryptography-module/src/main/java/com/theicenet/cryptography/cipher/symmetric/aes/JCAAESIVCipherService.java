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
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherServiceException;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
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
public class JCAAESIVCipherService implements SymmetricIVCipherService {

  private static final int AES_CIPHER_BLOCK_SIZE_16_BYTES = 16;
  private static final String IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES =
      "IV's size must be equals to AES cipher block size = %s bytes";

  private final BlockCipherIVModeOfOperation blockMode;

  public JCAAESIVCipherService(BlockCipherIVModeOfOperation blockMode) {
    this.blockMode = blockMode;
  }

  @Override
  public byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent) {
    return process(
        Cipher.ENCRYPT_MODE,
        blockMode,
        secretKey,
        iv,
        clearContent);
  }

  @Override
  public byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent) {
    return process(
        Cipher.DECRYPT_MODE,
        blockMode,
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
        blockMode,
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
        blockMode,
        secretKey,
        iv,
        encryptedContentInputStream,
        clearContentOutputStream);
  }

  private byte[] process(
      int operationMode,
      BlockCipherIVModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] content) {

    validateCipherParameters(blockMode, secretKey, iv);
    Validate.notNull(content);

    final AESPadding padding = paddingForBlockMode(blockMode);
    final Cipher cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);

    try {
      return cipher.doFinal(content);
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception processing AES content", e);
    }
  }

  private void process(
      int operationMode,
      BlockCipherIVModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      InputStream inputStream,
      OutputStream outputStream) {

    validateCipherParameters(blockMode, secretKey, iv);
    Validate.notNull(inputStream);
    Validate.notNull(outputStream);

    final AESPadding padding = paddingForBlockMode(blockMode);
    final Cipher cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);
    final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);

    try (inputStream; cipherOutputStream; outputStream) {
      inputStream.transferTo(cipherOutputStream);
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception processing AES content", e);
    }
  }

  private void validateCipherParameters(
      BlockCipherIVModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv) {

    Validate.notNull(blockMode);
    Validate.notNull(secretKey);
    Validate.notNull(iv);
    Validate.isTrue(
        iv.length == AES_CIPHER_BLOCK_SIZE_16_BYTES,
        String.format(
            IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES,
            AES_CIPHER_BLOCK_SIZE_16_BYTES));
  }

  private Cipher createCipher(
      Integer operationMode,
      BlockCipherIVModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      AESPadding padding) {

    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(String.format("AES/%s/%s", blockMode, padding));
      cipher.init(operationMode, secretKey, new IvParameterSpec(iv));
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception creating AES cipher", e);
    }

    return cipher;
  }

  private AESPadding paddingForBlockMode(BlockCipherIVModeOfOperation mode) {

    final AESPadding padding;
    switch (mode) {
      case CFB:
      case OFB:
      case CTR:
        padding = AESPadding.NOPADDING;
        break;
      case CBC:
        padding = AESPadding.PKCS5PADDING;
        break;
      default:
        throw new IllegalArgumentException(
            String.format(
                "Unsupported block cipher mode of operation [%s]",
                mode));
    }

    return padding;
  }
}
