package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2;

public enum ShaAlgorithm {
  SHA1("SHA1"),
  SHA256("SHA256"),
  SHA512("SHA512"),
  SHA3_256("SHA3-256"),
  SHA3_512("SHA3-512");

  private final String name;

  ShaAlgorithm(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return name;
  }
}
