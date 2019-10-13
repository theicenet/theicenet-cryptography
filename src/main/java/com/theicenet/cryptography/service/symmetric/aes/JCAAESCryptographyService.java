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

  @Override
  public byte[] encrypt(
      BlockCipherModeOfOperation mode,
      SecretKey secretKey,
      byte[] iv,
      byte[] message) {

    Validate.notNull(secretKey);
    Validate.notNull(secretKey);
    Validate.notNull(iv);
    Validate.isTrue(
        iv.length == AES_CIPHER_BLOCK_SIZE_16_BYTES,
        String.format(
            "iv size must be equals to AES cipher block size = %s bytes",
            AES_CIPHER_BLOCK_SIZE_16_BYTES));
    Validate.notNull(message);

    final Padding padding = inferPaddingFromModeOfOperation(mode);
    final Cipher cipher = createCipherToEncrypt(mode, secretKey, iv, padding);

    try {
      return cipher.doFinal(message);
    } catch (IllegalBlockSizeException e) {
      throw new AESIllegalBlockSizeException(e);
    } catch (BadPaddingException e) {
      throw new AESBadPaddingException(e);
    }
  }

  private Cipher createCipherToEncrypt(
      BlockCipherModeOfOperation mode,
      SecretKey secretKey,
      byte[] iv,
      Padding padding) {

    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(String.format("AES/%s/%s", mode, padding));
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new AESCipherNotFoundException(mode, padding);
    } catch (InvalidAlgorithmParameterException e) {
      throw new AESInvalidAlgorithmParameterException(e);
    } catch (InvalidKeyException e) {
      throw new AESInvalidKeyException(e);
    }

    return cipher;
  }

  private Padding inferPaddingFromModeOfOperation(BlockCipherModeOfOperation mode) {

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
