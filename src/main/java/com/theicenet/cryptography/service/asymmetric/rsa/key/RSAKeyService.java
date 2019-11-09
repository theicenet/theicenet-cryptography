package com.theicenet.cryptography.service.asymmetric.rsa.key;

import java.security.KeyPair;

public interface RSAKeyService {

  KeyPair generateKey(int keyLengthInBits);
}
