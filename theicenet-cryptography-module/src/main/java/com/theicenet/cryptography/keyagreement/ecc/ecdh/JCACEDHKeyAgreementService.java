package com.theicenet.cryptography.keyagreement.ecc.ecdh;

import com.theicenet.cryptography.key.asymmetric.ecc.ECCKeyAlgorithm;
import com.theicenet.cryptography.keyagreement.KeyAgreementService;
import com.theicenet.cryptography.keyagreement.KeyAgreementServiceException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;
import org.apache.commons.lang.Validate;

public class JCACEDHKeyAgreementService implements KeyAgreementService {

  private static final ECCKeyAlgorithm ECDH = ECCKeyAlgorithm.ECDH;

  @Override
  public byte[] generateSecretKey(PrivateKey privateKey, PublicKey publicKey) {
    Validate.notNull(privateKey);
    Validate.notNull(publicKey);

    KeyAgreement keyAgreement;
    try {
      keyAgreement = KeyAgreement.getInstance(ECDH.toString());
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(publicKey, true);
    } catch (Exception e) {
      throw new KeyAgreementServiceException(
          "Error generating key agreement component for algorithm ECDH",
          e);
    }

    return keyAgreement.generateSecret();
  }
}
