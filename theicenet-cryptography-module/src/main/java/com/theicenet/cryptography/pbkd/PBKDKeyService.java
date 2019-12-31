package com.theicenet.cryptography.pbkd;

import javax.crypto.SecretKey;

public interface PBKDKeyService {
  SecretKey generateKey(String password, byte[] salt, int keyLengthInBits);
}
