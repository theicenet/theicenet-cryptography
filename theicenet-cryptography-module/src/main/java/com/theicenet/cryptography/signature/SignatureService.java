package com.theicenet.cryptography.signature;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface SignatureService {

  byte[] sign(PrivateKey privateKey, byte[] content);

  /**
   * Signs and closes the passed stream.
   * Once this method returns the input stream have been closed so it can't be mutated.
   */
  byte[] sign(PrivateKey privateKey, InputStream contentInputStream);

  boolean verify(PublicKey publicKey, byte[] content, byte[] signature);

  /**
   * Verifies and closes the passed stream.
   * Once this method returns the input stream have been closed so it can't be mutated.
   */
  boolean verify(PublicKey publicKey, InputStream contentInputStream, byte[] signature);
}
