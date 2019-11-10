package com.theicenet.cryptography.service.symmetric.pbkd;

import javax.crypto.SecretKey;

public interface PBKDKeyService {
  SecretKey deriveKey(String password, byte[] salt, int keyLengthInBits);
}
