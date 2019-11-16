package com.theicenet.cryptography.service.symmetric.pbkd.argon2;

import com.theicenet.cryptography.service.symmetric.pbkd.PBKDKeyService;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.Validate;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.beans.factory.annotation.Value;

public class PBKDArgon2Service implements PBKDKeyService {

  private final Argon2Configuration argon2Configuration;

  public PBKDArgon2Service(
      @Value("${cryptography.keyDerivationFunction.argon2.type}") Argon2Type type,
      @Value("${cryptography.keyDerivationFunction.argon2.version}") Argon2Version version,
      @Value("${cryptography.keyDerivationFunction.argon2.iterations}") Integer iterations,
      @Value("${cryptography.keyDerivationFunction.argon2.memoryPowOfTwo}") Integer memoryPowOfTwo,
      @Value("${cryptography.keyDerivationFunction.argon2.parallelism}") Integer parallelism) {

    this.argon2Configuration =
        new Argon2Configuration(
            type,
            version,
            iterations,
            memoryPowOfTwo,
            parallelism);
  }

  @Override
  public SecretKey deriveKey(String password, byte[] salt, int keyLengthInBits) {
    Validate.notNull(password);
    Validate.notNull(salt);
    Validate.isTrue(keyLengthInBits > 0);

    final Argon2BytesGenerator argon2Generator =
        buildArgon2BytesGenerator(
            argon2Configuration,
            salt);

    byte[] generatedKey =
        generateKey(
            password,
            keyLengthInBits,
            argon2Generator);

    return new SecretKeySpec(generatedKey, argon2Configuration.getType().toString());
  }

  private Argon2BytesGenerator buildArgon2BytesGenerator(
      Argon2Configuration argon2Configuration,
      byte[] salt) {

    final var argon2Parameters =
        new Argon2Parameters.Builder(argon2Configuration.getType().getTypeCode())
            .withVersion(argon2Configuration.getVersion().getVersionCode())
            .withIterations(argon2Configuration.getIterations())
            .withMemoryPowOfTwo(argon2Configuration.getMemoryPowOfTwo())
            .withParallelism(argon2Configuration.getParallelism())
            .withSalt(salt)
            .build();

    final var argon2Generator = new Argon2BytesGenerator();
    argon2Generator.init(argon2Parameters);

    return argon2Generator;
  }

  private byte[] generateKey(
      String password,
      int keyLengthInBits,
      Argon2BytesGenerator argon2Generator) {

    byte[] generatedKey = new byte[keyLengthInBits / 8];
    argon2Generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), generatedKey);

    return generatedKey;
  }
}
