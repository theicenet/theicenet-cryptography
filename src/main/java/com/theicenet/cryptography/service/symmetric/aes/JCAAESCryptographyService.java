package com.theicenet.cryptography.service.symmetric.aes;

import com.theicenet.cryptography.service.symmetric.aes.exception.AESBadPaddingException;
import com.theicenet.cryptography.service.symmetric.aes.exception.AESCipherNotFoundException;
import com.theicenet.cryptography.service.symmetric.aes.exception.AESIllegalBlockSizeException;
import com.theicenet.cryptography.service.symmetric.aes.exception.AESInvalidAlgorithmParameterException;
import com.theicenet.cryptography.service.symmetric.aes.exception.AESInvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.lang.Validate;
import org.springframework.stereotype.Service;

@Service
public class JCAAESCryptographyService implements AESCryptographyService {

  private static final int AES_CIPHER_BLOCK_SIZE_16_BYTES = 16;
  private static final String IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES =
      "IV's size must be equals to AES cipher block size = %s bytes";

  @Override
  public byte[] encrypt(
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] clearContent) {

    return process(
        Cipher.ENCRYPT_MODE,
        blockMode,
        secretKey,
        iv,
        clearContent);
  }

  @Override
  public byte[] decrypt(
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] encryptedContent) {

    return process(
        Cipher.DECRYPT_MODE,
        blockMode,
        secretKey,
        iv,
        encryptedContent);
  }

  private byte[] process(
      Integer operationMode,
      BlockCipherModeOfOperation blockMode,
      SecretKey secretKey,
      byte[] iv,
      byte[] content) {

    Validate.notNull(operationMode);
    Validate.notNull(blockMode);
    Validate.notNull(secretKey);
    Validate.notNull(iv);
    Validate.isTrue(
        iv.length == AES_CIPHER_BLOCK_SIZE_16_BYTES,
        String.format(
            IV_SIZE_MUST_BE_EQUALS_TO_AES_CIPHER_BLOCK_SIZE_S_BYTES,
            AES_CIPHER_BLOCK_SIZE_16_BYTES));
    Validate.notNull(content);

    final Padding padding = paddingForBlockMode(blockMode);
    final Cipher cipher = createCipher(operationMode, blockMode, secretKey, iv, padding);

    try {
      return cipher.doFinal(content);
    } catch (IllegalBlockSizeException e) {
      throw new AESIllegalBlockSizeException(e);
    } catch (BadPaddingException e) {
      throw new AESBadPaddingException(e);
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
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new AESCipherNotFoundException(blockMode, padding);
    } catch (InvalidAlgorithmParameterException e) {
      throw new AESInvalidAlgorithmParameterException(e);
    } catch (InvalidKeyException e) {
      throw new AESInvalidKeyException(e);
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
