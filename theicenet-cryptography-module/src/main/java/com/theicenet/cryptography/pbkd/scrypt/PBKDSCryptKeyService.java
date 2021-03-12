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
package com.theicenet.cryptography.pbkd.scrypt;

import com.theicenet.cryptography.pbkd.PBKDKeyService;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.Validate;
import org.bouncycastle.crypto.generators.SCrypt;

/**
 * Bouncy Castle based component which implements Scrypt algorithm for password based key derivation
 * (PBKD).
 *
 * @see <a href="https://en.wikipedia.org/wiki/Scrypt">Scrypt</a>
 * @see <a href="https://en.wikipedia.org/wiki/Bouncy_Castle_(cryptography)">Bouncy Castle (cryptography)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class PBKDSCryptKeyService implements PBKDKeyService {

  private static final String SCRYPT = "SCrypt";

  private final SCryptConfiguration sCryptConfiguration;

  public PBKDSCryptKeyService(SCryptConfiguration sCryptConfiguration) {
    Validate.notNull(sCryptConfiguration);
    this.sCryptConfiguration = sCryptConfiguration;
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

    return new SecretKeySpec(
        generateKey(
            password,
            salt,
            keyLengthInBits,
            sCryptConfiguration),
        SCRYPT);
  }

  private byte[] generateKey(
      String password,
      byte[] salt,
      int keyLengthInBits,
      SCryptConfiguration sCryptConfiguration) {

    return SCrypt.generate(
        password.getBytes(StandardCharsets.UTF_8),
        salt,
        sCryptConfiguration.getCpuMemoryCost(),
        sCryptConfiguration.getBlockSize(),
        sCryptConfiguration.getParallelization(),
        keyLengthInBits / 8);
  }
}
