package com.theicenet.cryptography.pbkd.salt;

public interface SaltService {
  byte[] generateRandom(int saltLengthInBytes);
}
