package com.theicenet.cryptography.service.pbkd.scrypt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
final class SCryptConfiguration {
  private final Integer cpuMemoryCost;
  private final Integer blockSize;
  private final Integer parallelization;

  SCryptConfiguration(
      @Value("${cryptography.keyDerivationFunction.scrypt.cpuMemoryCost:1048576}") Integer cpuMemoryCost,
      @Value("${cryptography.keyDerivationFunction.scrypt.blockSize:8}") Integer blockSize,
      @Value("${cryptography.keyDerivationFunction.scrypt.parallelization:1}") Integer parallelization) {

    this.cpuMemoryCost = cpuMemoryCost;
    this.blockSize = blockSize;
    this.parallelization = parallelization;
  }

  Integer getCpuMemoryCost() {
    return cpuMemoryCost;
  }

  Integer getBlockSize() {
    return blockSize;
  }

  Integer getParallelization() {
    return parallelization;
  }
}
