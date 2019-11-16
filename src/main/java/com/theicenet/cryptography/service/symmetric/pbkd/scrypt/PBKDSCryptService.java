package com.theicenet.cryptography.service.symmetric.pbkd.scrypt;

import com.theicenet.cryptography.service.symmetric.pbkd.PBKDKeyService;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.Validate;
import org.bouncycastle.crypto.generators.SCrypt;
import org.springframework.beans.factory.annotation.Value;

public class PBKDSCryptService implements PBKDKeyService {

  private static final String SCRYPT = "SCrypt";

  private final SCryptConfiguration sCryptConfiguration;

  public PBKDSCryptService(
      @Value("${cryptography.keyDerivationFunction.scrypt.cpuMemoryCost}") Integer cpuMemoryCost,
      @Value("${cryptography.keyDerivationFunction.scrypt.blockSize}") Integer blockSize,
      @Value("${cryptography.keyDerivationFunction.scrypt.parallelization}") Integer parallelization) {

    this.sCryptConfiguration =
        new SCryptConfiguration(
            cpuMemoryCost,
            blockSize,
            parallelization);
  }

  @Override
  public SecretKey deriveKey(String password, byte[] salt, int keyLengthInBits) {
    Validate.notNull(password);
    Validate.notNull(salt);
    Validate.isTrue(keyLengthInBits > 0);

    return new SecretKeySpec(
        generateKey(
            sCryptConfiguration,
            password,
            salt,
            keyLengthInBits),
        SCRYPT);
  }

  private byte[] generateKey(
      SCryptConfiguration sCryptConfiguration,
      String password,
      byte[] salt,
      int keyLengthInBits) {

    return SCrypt.generate(
        password.getBytes(StandardCharsets.UTF_8),
        salt,
        sCryptConfiguration.getCpuMemoryCost(),
        sCryptConfiguration.getBlockSize(),
        sCryptConfiguration.getParallelization(),
        keyLengthInBits / 8);
  }
}
