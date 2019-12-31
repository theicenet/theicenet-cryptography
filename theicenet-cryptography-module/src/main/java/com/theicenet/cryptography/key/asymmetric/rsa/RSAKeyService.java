package com.theicenet.cryptography.key.asymmetric.rsa;

import java.security.KeyPair;

public interface RSAKeyService {

  KeyPair generateKey(int keyLengthInBits);
}
