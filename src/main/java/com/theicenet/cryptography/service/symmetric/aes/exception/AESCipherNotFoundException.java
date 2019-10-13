package com.theicenet.cryptography.service.symmetric.aes.exception;

import com.theicenet.cryptography.service.symmetric.aes.BlockCipherModeOfOperation;
import com.theicenet.cryptography.service.symmetric.aes.Padding;

public class AESCipherNotFoundException extends RuntimeException {

  public AESCipherNotFoundException(BlockCipherModeOfOperation mode, Padding padding) {
    super(String.format(
        "AES cipher no found for block cipher mode of operation [%s] and padding [%s]",
        mode,
        padding));
  }
}
