package com.theicenet.cryptography.service.asymmetric.dsa;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface DSASignatureService {

  byte[] sign(DSASignatureAlgorithm algorithm, PrivateKey privateKey, byte[] content);

  boolean verify(DSASignatureAlgorithm algorithm, PublicKey publicKey, byte[] content, byte[] signature);
}
