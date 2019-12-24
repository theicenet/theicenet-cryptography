package com.theicenet.cryptography.service.symmetric.aes;

public enum BlockCipherModeOfOperation {
  // ECB mode is intentionally excluded as it is NOT secure.
  CBC,
  CFB,
  OFB,
  CTR
}
