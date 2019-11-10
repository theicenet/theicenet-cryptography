package com.theicenet.cryptography.service.symmetric.salt;

public interface SaltService {
  byte[] generateRandom(int saltLengthInBytes);
}
