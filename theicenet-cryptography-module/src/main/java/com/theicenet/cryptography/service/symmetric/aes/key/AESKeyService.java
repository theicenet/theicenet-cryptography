package com.theicenet.cryptography.service.symmetric.aes.key;

import javax.crypto.SecretKey;

public interface AESKeyService {

  SecretKey generateKey(int keyLengthInBits);
}