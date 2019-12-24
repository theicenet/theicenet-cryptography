package com.theicenet.cryptography.service.symmetric.pbkd.argon2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
final class Argon2Configuration {
  private final Argon2Type type;
  private final Argon2Version version;
  private final Integer iterations;
  private final Integer memoryPowOfTwo;
  private final Integer parallelism;

  Argon2Configuration(
      @Value("${cryptography.keyDerivationFunction.argon2.type:ARGON2_ID}") Argon2Type type,
      @Value("${cryptography.keyDerivationFunction.argon2.version:ARGON2_VERSION_13}") Argon2Version version,
      @Value("${cryptography.keyDerivationFunction.argon2.iterations:3}") Integer iterations,
      @Value("${cryptography.keyDerivationFunction.argon2.memoryPowOfTwo:18}") Integer memoryPowOfTwo,
      @Value("${cryptography.keyDerivationFunction.argon2.parallelism:4}") Integer parallelism) {
    
    this.type = type;
    this.version = version;
    this.iterations = iterations;
    this.memoryPowOfTwo = memoryPowOfTwo;
    this.parallelism = parallelism;
  }

  Argon2Type getType() {
    return type;
  }

  Argon2Version getVersion() {
    return version;
  }

  Integer getIterations() {
    return iterations;
  }

  Integer getMemoryPowOfTwo() {
    return memoryPowOfTwo;
  }

  Integer getParallelism() {
    return parallelism;
  }
}
