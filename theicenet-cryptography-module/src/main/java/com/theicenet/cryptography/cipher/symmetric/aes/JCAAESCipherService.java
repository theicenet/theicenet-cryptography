package com.theicenet.cryptography.cipher.symmetric.aes;

import com.theicenet.cryptography.cipher.symmetric.SymmetricIVBasedCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.CipherOutputStream;
import org.apache.commons.lang.Validate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class JCAAESCipherService implements SymmetricIVBasedCipherService {

  private static final int AES_CIPHER_BLOCK_SIZE_16_BYTES = 16;
  private static final String IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES =
      "IV's size must be equals to AES cipher block size = %s bytes";

  private final BlockCipherIVBasedModeOfOperation blockMode;

  public JCAAESCipherService(BlockCipherIVBasedModeOfOperation blockMode) {
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
      BlockCipherIVBasedModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] content) {

    validateCipherParameters(blockMode, secretKey, iv);
    Validate.notNull(content);

    final var padding = paddingForBlockMode(blockMode);
    final var cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);

    try {
      return cipher.doFinal(content);
    } catch (Exception e) {
      throw new AESCipherServiceException("Exception processing content", e);
    }
  }

  private void process(
      int operationMode,
      BlockCipherIVBasedModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      InputStream inputStream,
      OutputStream outputStream) {

    validateCipherParameters(blockMode, secretKey, iv);
    Validate.notNull(inputStream);
    Validate.notNull(outputStream);

    final var padding = paddingForBlockMode(blockMode);
    final var cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);
    final var cipherOutputStream = new CipherOutputStream(outputStream, cipher);

    try (inputStream; cipherOutputStream; outputStream) {
      inputStream.transferTo(cipherOutputStream);
    } catch (Exception e) {
      throw new AESCipherServiceException("Exception processing content", e);
    }
  }

  private void validateCipherParameters(
      BlockCipherIVBasedModeOfOperation blockMode,
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
      BlockCipherIVBasedModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      Padding padding) {

    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(String.format("AES/%s/%s", blockMode, padding));
      cipher.init(operationMode, secretKey, new IvParameterSpec(iv));
    } catch (Exception e) {
      throw new AESCipherServiceException("Exception creating cipher", e);
    }

    return cipher;
  }

  private Padding paddingForBlockMode(BlockCipherIVBasedModeOfOperation mode) {

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
