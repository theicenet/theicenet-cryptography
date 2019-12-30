package com.theicenet.cryptography.service.asymmetric.rsa;

import com.theicenet.cryptography.provider.CryptographyProviderUtil;
import com.theicenet.cryptography.service.asymmetric.rsa.exception.RSACryptographyServiceException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;
import org.apache.commons.lang.Validate;

public class JCARSACryptographyService implements RSACryptographyService {

  public JCARSACryptographyService() {
    // For RSA/NONE/OAEP* & some sign algorithm it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] encrypt(RSAPadding padding, PublicKey publicKey, byte[] clearContent) {
    return process(Cipher.ENCRYPT_MODE, padding, publicKey, clearContent);
  }

  @Override
  public byte[] decrypt(RSAPadding padding, PrivateKey privateKey, byte[] encryptedContent) {
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

  @Override
  public byte[] sign(RSASignatureAlgorithm algorithm, PrivateKey privateKey, byte[] content) {
    Validate.notNull(algorithm);
    Validate.notNull(privateKey);
    Validate.notNull(content);

    try {
      final var signer = Signature.getInstance(algorithm.toString());
      signer.initSign(privateKey);
      signer.update(content);

      return signer.sign();
    } catch (Exception e) {
      throw new RSACryptographyServiceException("Exception signing content", e);
    }
  }

  @Override
  public boolean verify(
      RSASignatureAlgorithm algorithm,
      PublicKey publicKey,
      byte[] content,
      byte[] signature) {

    Validate.notNull(algorithm);
    Validate.notNull(publicKey);
    Validate.notNull(content);
    Validate.notNull(signature);

    try {
      final var verifier = Signature.getInstance(algorithm.toString());
      verifier.initVerify(publicKey);
      verifier.update(content);

      return verifier.verify(signature);
    } catch (Exception e) {
      throw new RSACryptographyServiceException("Exception verifying signature", e);
    }
  }
}
