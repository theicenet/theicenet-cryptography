package com.theicenet.cryptography.service.asymmetric.rsa;

import com.theicenet.cryptography.provider.CryptographyProviderUtil;
import com.theicenet.cryptography.service.asymmetric.rsa.exception.RSASignatureServiceException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.apache.commons.lang.Validate;

public class JCARSASignatureService implements RSASignatureService {

  private final RSASignatureAlgorithm algorithm;

  public JCARSASignatureService(RSASignatureAlgorithm algorithm) {
    Validate.notNull(algorithm);
    this.algorithm = algorithm;

    // For some sign/verify algorithms it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] content) {
    Validate.notNull(privateKey);
    Validate.notNull(content);

    try {
      final var signer = Signature.getInstance(algorithm.toString());
      signer.initSign(privateKey);
      signer.update(content);

      return signer.sign();
    } catch (Exception e) {
      throw new RSASignatureServiceException("Exception signing content", e);
    }
  }

  @Override
  public boolean verify(PublicKey publicKey, byte[] content, byte[] signature) {
    Validate.notNull(publicKey);
    Validate.notNull(content);
    Validate.notNull(signature);

    try {
      final var verifier = Signature.getInstance(algorithm.toString());
      verifier.initVerify(publicKey);
      verifier.update(content);

      return verifier.verify(signature);
    } catch (Exception e) {
      throw new RSASignatureServiceException("Exception verifying signature", e);
    }
  }
}
