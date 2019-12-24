package com.theicenet.cryptography.service.salt;

public interface SaltService {
  byte[] generateRandom(int saltLengthInBytes);
}
