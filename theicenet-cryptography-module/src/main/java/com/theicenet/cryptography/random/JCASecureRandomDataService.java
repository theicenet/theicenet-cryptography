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

import java.security.DrbgParameters;
import java.security.DrbgParameters.Capability;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;
import org.apache.commons.lang3.Validate;

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

  private static final List<Integer> VALID_STRENGTH_VALUES = List.of(112, 128, 192, 256);

  private final SecureRandom secureRandom;

  /**
   * Creates secure random data service based with a SecureRandom provider for the
   * specified algorithm.
   *
   * Please note that if the specified algorithm is DEFAULT, then this constructor will
   * create a secure random data service based on the default SecureRandom. The default SecureRandom
   * is platform dependant, and depends on different factors, like operating system, specific
   * configuration in java.security file, etc.
   *
   * If the specified algorithm is DRBG, then configuration will be picked up from
   * java.security#securerandom.drbg.config. Specific configuration can be set at the mentioned
   * configuration file.
   *
   * The default configuration for DRBG is
   *
   *    java.security#securerandom.drbg.config=Hash_DRBG,SHA-256,128,none
   *
   * @param algorithm algorithm to use for the secure random.
   */
  public JCASecureRandomDataService(SecureRandomAlgorithm algorithm) {
    Validate.notNull(algorithm);

    if (Objects.equals(algorithm, SecureRandomAlgorithm.DEFAULT)) {
      this.secureRandom = new SecureRandom();
      return;
    }

    try {
      this.secureRandom = SecureRandom.getInstance(algorithm.name());
    } catch (NoSuchAlgorithmException e) {
      throw new SecureRandomDataServiceException(
          String.format("Error creating SecureRandom instance for %s algorithm", algorithm),
          e);
    }
  }

  /**
   * Creates secure random data service based with the DRBG algorithm for the SecureRandom provider,
   * and the strength and capability specified, and with no personalization string
   *
   * Some other configuration properties for DRBG will be picked up from
   * java.security#securerandom.drbg.config.
   * Specific configuration can be set at the mentioned configuration file.
   *
   * @param strength security strength in bits
   * @param capability specify if prediction resistance or reseeding is needed
   */
  public JCASecureRandomDataService(int strength, SecureRandomCapability capability) {
    Validate.isTrue(
        VALID_STRENGTH_VALUES.contains(strength),
        String.format("DRBG strength must be a value in %s", VALID_STRENGTH_VALUES));
    Validate.notNull(capability);

    try {
      this.secureRandom =
          SecureRandom.getInstance(
              SecureRandomAlgorithm.DRBG.name(),
              DrbgParameters.instantiation(
                  strength,
                  Capability.valueOf(capability.name()),
                  null));
    } catch (NoSuchAlgorithmException e) {
      throw new SecureRandomDataServiceException(
          "Error creating SecureRandom instance for DRBG algorithm",
          e);
    }
  }

  /**
   * Creates secure random data service based with the DRBG algorithm for the SecureRandom provider,
   * and the strength, capability and personalizationString length specified.
   *
   * Some other configuration properties for DRBG will be picked up from
   * java.security#securerandom.drbg.config.
   * Specific configuration can be set at the mentioned configuration file.
   *
   * @param strength security strength in bits
   * @param capability specify if prediction resistance or reseeding is needed
   * @param personalizationStringLength personalization string length in bytes
   */
  public JCASecureRandomDataService(
      int strength,
      SecureRandomCapability capability,
      int personalizationStringLength) {

    Validate.isTrue(
        VALID_STRENGTH_VALUES.contains(strength),
        String.format("DRBG strength must be a value in %s", VALID_STRENGTH_VALUES));
    Validate.notNull(capability);
    Validate.isTrue(
        personalizationStringLength > 0,
        "Personalization string length must be bigger than zero");

    final byte[] personalisationString = new SecureRandom().generateSeed(personalizationStringLength);

    try {
      this.secureRandom =
          SecureRandom.getInstance(
              SecureRandomAlgorithm.DRBG.name(),
              DrbgParameters.instantiation(
                  strength,
                  Capability.valueOf(capability.name()),
                  personalisationString));
    } catch (NoSuchAlgorithmException e) {
      throw new SecureRandomDataServiceException(
          "Error creating SecureRandom instance for DRBG algorithm",
          e);
    }
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

  @Override
  public SecureRandom getSecureRandom() {
    return secureRandom;
  }
}
