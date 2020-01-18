package com.theicenet.cryptography.signature.ecdsa;

public enum ECDSASignatureAlgorithm {
  RIPEMD160withECDSA,
  SHA1withECDSA,
  SHA224withECDSA,
  SHA256withECDSA,
  SHA384withECDSA,
  SHA512withECDSA,
  SHA3_224withECDSA,
  SHA3_256withECDSA,
  SHA3_384withECDSA,
  SHA3_512withECDSA;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
