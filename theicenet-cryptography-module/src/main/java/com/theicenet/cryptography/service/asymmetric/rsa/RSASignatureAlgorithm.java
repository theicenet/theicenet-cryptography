package com.theicenet.cryptography.service.asymmetric.rsa;

public enum RSASignatureAlgorithm {
  SHA1withRSA,
  RIPEMD128withRSA,
  RIPEMD256withRSA,
  SHA256withRSA,
  SHA512withRSA,
  SHA3_256withRSA,
  SHA3_512withRSA,
  SHA1withRSAandMGF1,
  SHA256withRSAandMGF1,
  SHA512withRSAandMGF1;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
