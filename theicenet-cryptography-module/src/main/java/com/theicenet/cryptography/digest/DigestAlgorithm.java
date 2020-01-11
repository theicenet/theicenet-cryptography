package com.theicenet.cryptography.digest;

public enum DigestAlgorithm {
  MD5,
  SHA_1,
  SHA_224,
  SHA_256,
  SHA_384,
  SHA_512,
  SHA3_224,
  SHA3_256,
  SHA3_384,
  SHA3_512,
  KECCAK_224,
  KECCAK_256,
  KECCAK_288,
  KECCAK_384,
  KECCAK_512,
  Whirlpool,
  Tiger,
  SM3;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
