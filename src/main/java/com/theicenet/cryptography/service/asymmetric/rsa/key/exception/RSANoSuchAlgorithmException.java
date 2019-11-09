package com.theicenet.cryptography.service.asymmetric.rsa.key.exception;

import java.security.NoSuchAlgorithmException;

public class RSANoSuchAlgorithmException extends RuntimeException {

  public RSANoSuchAlgorithmException(NoSuchAlgorithmException e) {
    super(e);
  }
}
