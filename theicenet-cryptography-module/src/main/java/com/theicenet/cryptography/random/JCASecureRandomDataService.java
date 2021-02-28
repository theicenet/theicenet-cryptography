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
package com.theicenet.cryptography.random;

import java.security.SecureRandom;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which generates <b>cryptographically secure random data</b>
 *
 * @see <a href="https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator">Cryptographically secure pseudorandom number generator</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCASecureRandomDataService implements SecureRandomDataService {

  private final SecureRandom secureRandom;

  public JCASecureRandomDataService(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  /**
   * @implNote Produced data is <b>secure random</b> generated as requested in the API interface.
   */
  @Override
  public byte[] generateSecureRandomData(int lengthInBytes) {
    Validate.isTrue(lengthInBytes > 0);

    final byte[] randomBytes = new byte[lengthInBytes];
    secureRandom.nextBytes(randomBytes);

    return randomBytes;
  }
}
