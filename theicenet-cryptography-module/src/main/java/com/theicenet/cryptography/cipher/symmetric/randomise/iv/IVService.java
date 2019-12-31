package com.theicenet.cryptography.cipher.symmetric.randomise.iv;

public interface IVService {

  byte[] generateRandom(int ivLengthInBytes);
}
