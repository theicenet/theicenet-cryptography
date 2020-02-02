package com.theicenet.cryptography.signature.rsa;

public enum RSASignatureAlgorithm {
  NonewithRSA,
  RIPEMD128withRSA,
  RIPEMD160withRSA,
  RIPEMD256withRSA,
  SHA1withRSA,
  SHA224withRSA,
  SHA256withRSA,
  SHA384withRSA,
  SHA512withRSA,
  SHA3_224withRSA,
  SHA3_256withRSA,
  SHA3_384withRSA,
  SHA3_512withRSA,
  SHA1withRSAandMGF1,
  SHA256withRSAandMGF1,
  SHA384withRSAandMGF1,
  SHA512withRSAandMGF1,
  SHA1WithRSA_PSS,
  SHA224withRSA_PSS,
  SHA256withRSA_PSS,
  SHA384withRSA_PSS,
  SHA512withRSA_PSS;

  @Override
  public String toString() {
    return name()
        .replace("_PSS", "/PSS")
        .replace("_", "-");
  }
}
