package com.theicenet.cryptography.service.pbkd.scrypt;

public final class SCryptConfiguration {
  private final Integer cpuMemoryCost;
  private final Integer blockSize;
  private final Integer parallelization;

  public SCryptConfiguration(Integer cpuMemoryCost, Integer blockSize, Integer parallelization) {

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
