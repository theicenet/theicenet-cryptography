package com.theicenet.cryptography.digest;

import java.io.InputStream;

public interface DigestService {

  byte[] digest(byte[] content);

  /**
   * Digests and closes the passed stream.
   * Once this method returns the input stream have been closed so it can't be mutated.
   */
  byte[] digest(InputStream contentInputStream);
}
