package com.theicenet.cryptography.service.symmetric.aes;

import com.theicenet.cryptography.service.symmetric.aes.exception.AESCryptographyServiceException;
import org.apache.commons.lang.Validate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class JCAAESCryptographyService implements AESCryptographyService {

  private static final int AES_CIPHER_BLOCK_SIZE_16_BYTES = 16;
  private static final String IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES =
      "IV's size must be equals to AES cipher block size = %s bytes";

  private final BlockCipherModeOfOperation blockMode;

  public JCAAESCryptographyService(BlockCipherModeOfOperation blockMode) {
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

  private byte[] process(
      int operationMode,
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] content) {

    Validate.notNull(blockMode);
    Validate.notNull(secretKey);
    Validate.notNull(iv);
    Validate.isTrue(
        iv.length == AES_CIPHER_BLOCK_SIZE_16_BYTES,
        String.format(
            IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES,
            AES_CIPHER_BLOCK_SIZE_16_BYTES));
    Validate.notNull(content);

    final var padding = paddingForBlockMode(blockMode);
    final var cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);

    try {
      return cipher.doFinal(content);
    } catch (Exception e) {
      throw new AESCryptographyServiceException("Exception processing content", e);
    }
  }

  private Cipher createCipher(
      Integer operationMode,
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      Padding padding) {

    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(String.format("AES/%s/%s", blockMode, padding));
      cipher.init(operationMode, secretKey, new IvParameterSpec(iv));
    } catch (Exception e) {
      throw new AESCryptographyServiceException("Exception creating cipher", e);
    }

    return cipher;
  }

  private Padding paddingForBlockMode(BlockCipherModeOfOperation mode) {

    final Padding padding;
    switch (mode) {
      case CFB:
      case OFB:
      case CTR:
        padding = Padding.NOPADDING;
        break;
      case CBC:
        padding = Padding.PKCS5PADDING;
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
