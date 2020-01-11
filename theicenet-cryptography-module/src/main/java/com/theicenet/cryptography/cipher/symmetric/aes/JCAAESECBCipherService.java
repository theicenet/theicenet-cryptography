package com.theicenet.cryptography.cipher.symmetric.aes;

import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import org.apache.commons.lang.Validate;

public class JCAAESECBCipherService implements SymmetricCipherService {

  private static final String AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5PADDING";

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

    final var cipher = createCipher(operationMode, secretKey);

    try {
      return cipher.doFinal(content);
    } catch (Exception e) {
      throw new AESCipherServiceException("Exception processing content", e);
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

    final var cipher = createCipher(operationMode, secretKey);
    final var cipherOutputStream = new CipherOutputStream(outputStream, cipher);

    try (inputStream; cipherOutputStream; outputStream) {
      inputStream.transferTo(cipherOutputStream);
    } catch (Exception e) {
      throw new AESCipherServiceException("Exception processing content", e);
    }
  }

  private Cipher createCipher(Integer operationMode, SecretKey secretKey) {

    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(AES_ECB_PKCS5PADDING);
      cipher.init(operationMode, secretKey);
    } catch (Exception e) {
      throw new AESCipherServiceException("Exception creating cipher", e);
    }

    return cipher;
  }
}
