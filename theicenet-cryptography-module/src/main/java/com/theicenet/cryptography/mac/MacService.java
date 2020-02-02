package com.theicenet.cryptography.mac;

import java.io.InputStream;
import javax.crypto.SecretKey;

public interface MacService {

  byte[] calculateMac(SecretKey secretKey, byte[] content);

  /**
   * Calculates MAC and closes the passed stream.
   * Once this method returns the input stream have been closed so it can't be mutated.
   */
  byte[] calculateMac(SecretKey secretKey, InputStream contentInputStream);
}
