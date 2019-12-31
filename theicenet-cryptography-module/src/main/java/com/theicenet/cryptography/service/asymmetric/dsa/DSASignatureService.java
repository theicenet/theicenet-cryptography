package com.theicenet.cryptography.service.asymmetric.dsa;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface DSASignatureService {

  byte[] sign(PrivateKey privateKey, byte[] content);

  boolean verify(PublicKey publicKey, byte[] content, byte[] signature);
}
