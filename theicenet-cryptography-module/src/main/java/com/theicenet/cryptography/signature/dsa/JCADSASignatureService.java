package com.theicenet.cryptography.signature.dsa;

import com.theicenet.cryptography.signature.SignatureService;
import com.theicenet.cryptography.signature.common.JCACommonSignature;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.commons.lang.Validate;

public class JCADSASignatureService implements SignatureService {

  private final DSASignatureAlgorithm algorithm;

  public JCADSASignatureService(DSASignatureAlgorithm algorithm) {
    Validate.notNull(algorithm);
    this.algorithm = algorithm;

    // For some sign/verify algorithms it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] content) {
    return JCACommonSignature.sign(privateKey, content, algorithm.toString());
  }

  @Override
  public byte[] sign(PrivateKey privateKey, InputStream contentInputStream) {
    return JCACommonSignature.sign(privateKey, contentInputStream, algorithm.toString());
  }

  @Override
  public boolean verify(PublicKey publicKey, byte[] content, byte[] signature) {
    return JCACommonSignature.verify(publicKey, content, signature, algorithm.toString());
  }

  @Override
  public boolean verify(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    return JCACommonSignature.verify(publicKey, contentInputStream, signature, algorithm.toString());
  }
}
