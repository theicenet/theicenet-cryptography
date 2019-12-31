package com.theicenet.cryptography.cipher.asymmetric.rsa;

import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCryptographyService;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import org.apache.commons.lang.Validate;

public class JCARSACryptographyService implements AsymmetricCryptographyService {

  private final RSAPadding padding;

  public JCARSACryptographyService(RSAPadding padding) {
    this.padding = padding;

    // For RSA/NONE/OAEP* it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] encrypt(PublicKey publicKey, byte[] clearContent) {
    return process(Cipher.ENCRYPT_MODE, padding, publicKey, clearContent);
  }

  @Override
  public byte[] decrypt(PrivateKey privateKey, byte[] encryptedContent) {
    return process(Cipher.DECRYPT_MODE, padding, privateKey, encryptedContent);
  }

  private byte[] process(int operationMode, RSAPadding padding, Key key, byte[] content) {
    Validate.notNull(padding);
    Validate.notNull(key);
    Validate.notNull(content);

    try {
      final var cipher = Cipher.getInstance(String.format("RSA/NONE/%s", padding.toString()));
      cipher.init(operationMode, key);

      return cipher.doFinal(content);
    } catch (Exception e) {
      throw new RSACryptographyServiceException("Exception encrypting/decrypting content", e);
    }
  }
}
