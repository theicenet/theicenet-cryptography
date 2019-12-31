package com.theicenet.cryptography.cipher.symmetric.aes.iv;

public interface IVService {

  byte[] generateRandom(int ivLengthInBytes);
}
