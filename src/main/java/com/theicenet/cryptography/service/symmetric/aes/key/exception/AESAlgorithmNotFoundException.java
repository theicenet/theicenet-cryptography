package com.theicenet.cryptography.service.symmetric.aes.key.exception;

public class AESAlgorithmNotFoundException extends RuntimeException {

  public AESAlgorithmNotFoundException(String algorithm, Throwable cause) {
    super(String.format("Key generation algorithm %s not found", algorithm), cause);
  }
}
