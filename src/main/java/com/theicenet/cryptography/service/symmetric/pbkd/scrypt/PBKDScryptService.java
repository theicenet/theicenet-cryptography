package com.theicenet.cryptography.service.symmetric.pbkd.scrypt;

import com.theicenet.cryptography.service.symmetric.pbkd.PBKDKeyService;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.SCrypt;
import org.springframework.beans.factory.annotation.Value;

public class PBKDScryptService implements PBKDKeyService {

  private static final String SCRYPT = "SCrypt";

  private final Integer cpuMemoryCost;
  private final Integer blockSize;
  private final Integer parallelization;

  public PBKDScryptService(
      @Value("${cryptography.keyDerivationFunction.scrypt.cpuMemoryCost}") Integer cpuMemoryCost,
      @Value("${cryptography.keyDerivationFunction.scrypt.blockSize}") Integer blockSize,
      @Value("${cryptography.keyDerivationFunction.scrypt.parallelization}") Integer parallelization) {

    this.cpuMemoryCost = cpuMemoryCost;
    this.blockSize = blockSize;
    this.parallelization = parallelization;
  }

  @Override
  public SecretKey deriveKey(String password, byte[] salt, int keyLengthInBits) {
    final var generatedKey =
        SCrypt.generate(
            password.getBytes(StandardCharsets.UTF_8),
            salt,
            cpuMemoryCost,
            blockSize,
            parallelization,
            keyLengthInBits / 8);

    return new SecretKeySpec(generatedKey, SCRYPT);
  }
}
