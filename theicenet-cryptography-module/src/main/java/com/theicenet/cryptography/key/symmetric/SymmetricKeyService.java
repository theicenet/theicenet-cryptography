package com.theicenet.cryptography.key.symmetric;

import javax.crypto.SecretKey;

public interface SymmetricKeyService {

  SecretKey generateKey(int keyLengthInBits);
}
