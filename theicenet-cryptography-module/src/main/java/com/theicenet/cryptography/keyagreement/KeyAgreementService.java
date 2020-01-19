package com.theicenet.cryptography.keyagreement;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyAgreementService {

  byte[] generateSecretKey(PrivateKey privateKey, PublicKey publicKey);
}
