package com.theicenet.cryptography.key.symmetric.aes;

import javax.crypto.SecretKey;

public interface AESKeyService {

  SecretKey generateKey(int keyLengthInBits);
}
