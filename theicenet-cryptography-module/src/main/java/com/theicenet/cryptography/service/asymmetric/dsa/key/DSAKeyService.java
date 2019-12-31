package com.theicenet.cryptography.service.asymmetric.dsa.key;

import java.security.KeyPair;

public interface DSAKeyService {

  KeyPair generateKey(int keyLengthInBits);
}
