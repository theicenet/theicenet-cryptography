/*
 * Copyright 2019-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.theicenet.cryptography.pbkd.argon2;

import com.theicenet.cryptography.pbkd.PBKDKeyService;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.Validate;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Bouncy Castle based component which implements Argon2 algorithm for password based key derivation
 * (PBKD).
 *
 * @see <a href="https://en.wikipedia.org/wiki/Argon2">Argon2</a>
 * @see <a href="https://en.wikipedia.org/wiki/Bouncy_Castle_(cryptography)">Bouncy Castle (cryptography)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class PBKDArgon2KeyService implements PBKDKeyService {

  private final Argon2Configuration argon2Configuration;

  public PBKDArgon2KeyService(Argon2Configuration argon2Configuration) {
    Validate.notNull(argon2Configuration);
    this.argon2Configuration = argon2Configuration;
  }

  /**
   *
   * @implNote For a given component configuration, the generated final key is repeatable and
   *           deterministic as requested in the API interface. Same entry produces always the
   *           same result.
   */
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

    final Argon2BytesGenerator argon2BytesGenerator = new Argon2BytesGenerator();
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
