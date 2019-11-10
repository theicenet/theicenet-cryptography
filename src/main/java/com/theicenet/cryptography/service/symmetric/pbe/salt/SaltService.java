package com.theicenet.cryptography.service.symmetric.pbe.salt;

public interface SaltService {
  byte[] generateRandom(int saltLengthInBytes);
}
