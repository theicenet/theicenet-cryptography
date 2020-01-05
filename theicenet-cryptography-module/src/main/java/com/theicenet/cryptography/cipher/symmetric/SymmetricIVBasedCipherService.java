package com.theicenet.cryptography.cipher.symmetric;

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;

public interface SymmetricIVBasedCipherService {

  byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] clearContent);

  /**
   * Encrypts and closes the passed streams.
   * Once this method returns the input and output streams have been closed so they can't be mutated.
   */
  void encrypt(
      SecretKey secretKey,
      byte[] iv,
      InputStream clearContentInputStream,
      OutputStream encryptedContentOutputStream);

  byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encryptedContent);

  /**
   * Encrypts and closes the passed streams.
   * Once this method returns the input and output streams have been closed so they can't be mutated.
   */
  void decrypt(
      SecretKey secretKey,
      byte[] iv,
      InputStream encryptedContentInputStream,
      OutputStream clearContentOutputStream);
}
