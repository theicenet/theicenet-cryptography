package com.theicenet.cryptography.service.asymmetric.rsa;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface RSASignatureService {

  byte[] sign(RSASignatureAlgorithm algorithm, PrivateKey privateKey, byte[] content);

  boolean verify(RSASignatureAlgorithm algorithm, PublicKey publicKey, byte[] content,
      byte[] signature);
}
