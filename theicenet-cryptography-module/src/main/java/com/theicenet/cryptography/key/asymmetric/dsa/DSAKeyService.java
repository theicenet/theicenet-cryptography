package com.theicenet.cryptography.key.asymmetric.dsa;

import java.security.KeyPair;

public interface DSAKeyService {

  KeyPair generateKey(int keyLengthInBits);
}
