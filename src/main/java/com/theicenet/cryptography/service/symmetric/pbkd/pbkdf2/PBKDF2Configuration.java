package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2;

final class PBKDF2Configuration {
  private final String algorithm;
  private final Integer iterations;

  PBKDF2Configuration(String algorithm, Integer iterations) {
    this.algorithm = algorithm;
    this.iterations = iterations;
  }

  String getAlgorithm() {
    return algorithm;
  }

  Integer getIterations() {
    return iterations;
  }
}
