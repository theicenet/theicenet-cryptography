package com.theicenet.cryptography.service.symmetric.aes.iv;

public interface IVService {

  byte[] generateRandom(int ivLengthInBytes);
}
