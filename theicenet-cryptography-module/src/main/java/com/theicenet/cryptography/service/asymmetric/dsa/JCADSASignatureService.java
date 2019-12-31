package com.theicenet.cryptography.service.asymmetric.dsa;

import com.theicenet.cryptography.provider.CryptographyProviderUtil;
import com.theicenet.cryptography.service.asymmetric.dsa.exception.DSASignatureServiceException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.apache.commons.lang.Validate;

public class JCADSASignatureService implements DSASignatureService {

  public JCADSASignatureService() {
    // For some sign/verify algorithms it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] sign(DSASignatureAlgorithm algorithm, PrivateKey privateKey, byte[] content) {
    Validate.notNull(algorithm);
    Validate.notNull(privateKey);
    Validate.notNull(content);

    try {
      final var signer = Signature.getInstance(algorithm.toString());
      signer.initSign(privateKey);
      signer.update(content);

      return signer.sign();
    } catch (Exception e) {
      throw new DSASignatureServiceException("Exception signing content", e);
    }
  }

  @Override
  public boolean verify(
      DSASignatureAlgorithm algorithm,
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
      throw new DSASignatureServiceException("Exception verifying signature", e);
    }
  }
}
