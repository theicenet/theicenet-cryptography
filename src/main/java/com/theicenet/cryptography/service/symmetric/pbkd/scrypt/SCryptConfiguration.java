package com.theicenet.cryptography.service.symmetric.pbkd.scrypt;

import javax.annotation.concurrent.Immutable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Immutable
@Component
final class SCryptConfiguration {
  private final Integer cpuMemoryCost;
  private final Integer blockSize;
  private final Integer parallelization;

  SCryptConfiguration(
      @Value("${cryptography.keyDerivationFunction.scrypt.cpuMemoryCost}") Integer cpuMemoryCost,
      @Value("${cryptography.keyDerivationFunction.scrypt.blockSize}") Integer blockSize,
      @Value("${cryptography.keyDerivationFunction.scrypt.parallelization}") Integer parallelization) {

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
