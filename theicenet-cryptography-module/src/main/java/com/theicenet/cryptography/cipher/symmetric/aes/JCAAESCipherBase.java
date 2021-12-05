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
import static java.util.Objects.isNull;

import com.theicenet.cryptography.cipher.symmetric.BlockCipherModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.InvalidAuthenticationTagException;
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherServiceException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.lang3.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.2.0
 */
public abstract class JCAAESCipherBase {

  private static final int AES_CIPHER_BLOCK_SIZE_16_BYTES = 16;
  private static final String IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES =
      "IV's size must be equals to AES cipher block size = %s bytes";

  private static final String IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_16_BYTES =
      String.format(
          IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES,
          AES_CIPHER_BLOCK_SIZE_16_BYTES);

  private static final int AUTHENTICATED_TAG_SIZE_128_BITS = 128;

  protected byte[] process(
      int operationMode,
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] content,
      byte[]... associatedData) {

    Validate.notNull(blockMode);
    Validate.notNull(secretKey);
    validateIV(iv);
    Validate.notNull(content);

    final AESPadding padding = paddingForBlockMode(blockMode);
    final Cipher cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);
    cipher.updateAAD(concat(associatedData));

    try {
      return cipher.doFinal(content);
    } catch (AEADBadTagException e) {
      throw new InvalidAuthenticationTagException("Invalid authentication tag", e);
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception processing AES content", e);
    }
  }

  protected void process(
      int operationMode,
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      InputStream inputStream,
      OutputStream outputStream,
      byte[]... associatedData) {

    Validate.notNull(blockMode);
    Validate.notNull(secretKey);
    validateIV(iv);
    Validate.notNull(inputStream);
    Validate.notNull(outputStream);

    final AESPadding padding = paddingForBlockMode(blockMode);
    final Cipher cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);
    cipher.updateAAD(concat(associatedData));

    final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);

    try (inputStream; cipherOutputStream; outputStream) {
      inputStream.transferTo(cipherOutputStream);
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception processing AES content", e);
    }
  }

  private Cipher createCipher(
      Integer operationMode,
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      AESPadding padding) {

    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(String.format("AES/%s/%s", blockMode, padding));
      switch (blockMode) {
        case ECB:
          cipher.init(operationMode, secretKey);
          break;
        case CBC:
        case CFB:
        case OFB:
        case CTR:
          cipher.init(operationMode, secretKey, new IvParameterSpec(iv));
          break;
        case GCM:
          cipher.init(operationMode, secretKey, new GCMParameterSpec(AUTHENTICATED_TAG_SIZE_128_BITS, iv));
          break;
        default:
          throw new IllegalArgumentException(
              String.format(
                  "Unsupported block cipher mode of operation [%s]",
                  blockMode));
      }
    } catch (Exception e) {
      throw new SymmetricCipherServiceException("Exception creating AES cipher", e);
    }

    return cipher;
  }

  private AESPadding paddingForBlockMode(BlockCipherModeOfOperation mode) {
    switch (mode) {
      case CFB:
      case OFB:
      case CTR:
      case GCM:
        return AESPadding.NOPADDING;
      case ECB:
      case CBC:
        return AESPadding.PKCS5PADDING;
      default:
        throw new IllegalArgumentException(
            String.format(
                "Unsupported block cipher mode of operation [%s]",
                mode));
    }
  }

  private void validateIV(byte[] iv) {
    if (isNull(iv)) {
      return;
    }

    Validate.isTrue(
        iv.length == AES_CIPHER_BLOCK_SIZE_16_BYTES,
        IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_16_BYTES);
  }
}
