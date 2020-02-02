package com.theicenet.cryptography.pbkd.argon2;

import com.theicenet.cryptography.pbkd.PBKDKeyService;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.Validate;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class PBKDArgon2KeyService implements PBKDKeyService {

  private final Argon2Configuration argon2Configuration;

  public PBKDArgon2KeyService(Argon2Configuration argon2Configuration) {
    this.argon2Configuration = argon2Configuration;
  }

  @Override
  public SecretKey generateKey(String password, byte[] salt, int keyLengthInBits) {
    Validate.notNull(password);
    Validate.notNull(salt);
    Validate.isTrue(keyLengthInBits > 0);

    byte[] generatedKey =
        generateKeyAsByteArray(
            password,
            salt,
            keyLengthInBits);

    return new SecretKeySpec(generatedKey, argon2Configuration.getType().toString());
  }

  private byte[] generateKeyAsByteArray(
      String password,
      byte[] salt,
      int keyLengthInBits) {

    final Argon2BytesGenerator argon2BytesGenerator =
        buildArgon2BytesGenerator(
            argon2Configuration,
            salt);

    byte[] generatedKey = new byte[keyLengthInBits / 8];
    argon2BytesGenerator.generateBytes(password.getBytes(StandardCharsets.UTF_8), generatedKey);

    return generatedKey;
  }

  private Argon2BytesGenerator buildArgon2BytesGenerator(
      Argon2Configuration argon2Configuration,
      byte[] salt) {

    final var argon2BytesGenerator = new Argon2BytesGenerator();
    argon2BytesGenerator.init(buildArgon2Parameters(argon2Configuration, salt));

    return argon2BytesGenerator;
  }

  private Argon2Parameters buildArgon2Parameters(
      Argon2Configuration argon2Configuration,
      byte[] salt) {

    return new Argon2Parameters.Builder(argon2Configuration.getType().getTypeCode())
        .withVersion(argon2Configuration.getVersion().getVersionCode())
        .withIterations(argon2Configuration.getIterations())
        .withMemoryPowOfTwo(argon2Configuration.getMemoryPowOfTwo())
        .withParallelism(argon2Configuration.getParallelism())
        .withSalt(salt)
        .build();
  }
}
