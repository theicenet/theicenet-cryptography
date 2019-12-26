package com.theicenet.cryptography.service.pbkd.pbkdf2;

public enum ShaAlgorithm {
  SHA1,
  SHA256,
  SHA512,
  SHA3_256,
  SHA3_512;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
