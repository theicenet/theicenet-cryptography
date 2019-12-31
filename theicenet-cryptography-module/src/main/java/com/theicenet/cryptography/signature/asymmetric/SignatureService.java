package com.theicenet.cryptography.signature.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SignatureService {

  byte[] sign(PrivateKey privateKey, byte[] content);

  boolean verify(PublicKey publicKey, byte[] content, byte[] signature);
}
