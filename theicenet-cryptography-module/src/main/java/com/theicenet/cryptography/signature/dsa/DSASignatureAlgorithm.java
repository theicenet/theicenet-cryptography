package com.theicenet.cryptography.signature.dsa;

public enum DSASignatureAlgorithm {
  SHA1withDSA,
  SHA224withDSA,
  SHA256withDSA,
  SHA384withDSA,
  SHA512withDSA,
  SHA3_224withDSA,
  SHA3_256withDSA,
  SHA3_384withDSA,
  SHA3_512withDSA;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
