package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2.exception;

public class PBKDAlgorithmNotFoundException extends RuntimeException {

  public PBKDAlgorithmNotFoundException(String algorithm, Throwable cause) {
    super(String.format("PBE key generation algorithm %s not found", algorithm), cause);
  }
}
