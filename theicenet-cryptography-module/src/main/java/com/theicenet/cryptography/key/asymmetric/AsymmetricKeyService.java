package com.theicenet.cryptography.key.asymmetric;

import java.security.KeyPair;

public interface AsymmetricKeyService {

  KeyPair generateKey(int keyLengthInBits);
}
