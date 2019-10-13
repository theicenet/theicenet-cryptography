package com.theicenet.cryptography.service.symmetric.aes.key.exception;

public class KeyGenerationAlgorithmNotFoundException extends RuntimeException {

  public KeyGenerationAlgorithmNotFoundException(String algorithm, Throwable cause) {
    super(String.format("Key generation algorithm %s not found", algorithm), cause);
  }
}
