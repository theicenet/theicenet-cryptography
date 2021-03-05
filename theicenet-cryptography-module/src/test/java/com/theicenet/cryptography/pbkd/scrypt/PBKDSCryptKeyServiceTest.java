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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.pbkd.PBKDKeyService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Juan Fidalgo
 */
class PBKDSCryptKeyServiceTest {

  static final int KEY_LENGTH_64_BITS = 64;
  static final int KEY_LENGTH_128_BITS = 128;
  static final int KEY_LENGTH_256_BITS = 256;
  static final int KEY_LENGTH_512_BITS = 512;
  static final int KEY_LENGTH_1024_BITS = 1024;

  final String RAW = "RAW";

  final String SCRYPT = "SCrypt";

  final int CPU_MEMORY_COST_1024 = 1024;
  final int BLOCK_SIZE_8 = 8;
  final int PARALLELIZATION = 1;

  static final String PASSWORD_1234567890_80_BITS = "1234567890";
  final String PASSWORD_0123456789_80_BITS = "0123456789";

  final byte[] SECRET_BYTE_ARRAY_80_BITS =
      new byte[]{6, 11, 76, -39, 65, 43, -124, 111, -119, -51};

  static final byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES =
      "ZYXWVUTSRQPONMLKJIHG".getBytes(StandardCharsets.UTF_8);

  static final byte[] SCRYPT_HASH_128_BITS =
      HexUtil.decodeHex("accbf0d4873bae1315fa16e1f8840dd8");

  static final byte[] SCRYPT_HASH_256_BITS =
      HexUtil.decodeHex("accbf0d4873bae1315fa16e1f8840dd8b09a2a270cfdef1afd65d3039bd97188");

  static final byte[] SCRYPT_HASH_256_BITS_FOR_SECRET_BYTE_ARRAY =
      HexUtil.decodeHex("3aa92b5d73f1241151fbab13460d28361b5a37a714735c806d69a5075fba9f48");

  static final byte[] SCRYPT_HASH_512_BITS =
      HexUtil.decodeHex(
          "accbf0d4873bae1315fa16e1f8840dd8b09a2a270cfde"
              + "f1afd65d3039bd97188a52028d4b3ac6ccf7e6b9424e"
              + "ef9d1ecf9ce976f173e8e41b2d981b8bdf88e53");

  static final byte[] SCRYPT_HASH_1024_BITS =
      HexUtil.decodeHex(
          "accbf0d4873bae1315fa16e1f8840dd8b09a2a270cfdef"
              + "1afd65d3039bd97188a52028d4b3ac6ccf7e6b9424eef"
              + "9d1ecf9ce976f173e8e41b2d981b8bdf88e530c2101bf"
              + "22dc9ab2f4664bbbeba35d0e2f7585590daad012ceb64"
              + "31060f09340ae0f35d85f59736e62768e4a59d1e7ed6a"
              + "f77c77825a7ffd4871120c8cb41291");

  PBKDKeyService pbkdKeyService;

  @BeforeEach
  void setUp() {
    pbkdKeyService =
        new PBKDSCryptKeyService(
            new SCryptConfiguration(
                CPU_MEMORY_COST_1024,
                BLOCK_SIZE_8,
                PARALLELIZATION));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNullPassword() {
    // Given
    final String NULL_PASSWORD = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                NULL_PASSWORD,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_128_BITS));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNullSalt() {
    // Given
    final byte[] NULL_SALT = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                NULL_SALT,
                KEY_LENGTH_128_BITS));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNegativeKeyLength() {
    // Given
    final var KEY_LENGTH_MINUS_ONE = -1;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_MINUS_ONE));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndZeroKeyLength() {
    // Given
    final var KEY_LENGTH_ZERO = 0;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_ZERO));
  }

  @Test
  void producesNotNullWhenGeneratingKey() {
    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesKeyWithRightAlgorithmWhenGeneratingKey() {
    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(SCRYPT)));
  }

  @Test
  void producesKeyWithRAWFormatWhenGeneratingKey() {
    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo(RAW)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_64_BITS,
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS,
      KEY_LENGTH_512_BITS,
      KEY_LENGTH_1024_BITS})
  void producesKeyWithTheRequestedLengthWhenGeneratingKey(Integer keyLength) {
    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(keyLength)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_64_BITS,
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS,
      KEY_LENGTH_512_BITS,
      KEY_LENGTH_1024_BITS})
  void producesTheSameKeyWhenGeneratingTwoConsecutiveKeysWithTheSamePasswordSaltAndLength(Integer keyLength) {
    // When generating two consecutive keys with the same password, salt and length
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then the generated keys are the same
    assertThat(generatedKey_1.getEncoded(), is(equalTo(generatedKey_2.getEncoded())));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_64_BITS,
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS,
      KEY_LENGTH_512_BITS,
      KEY_LENGTH_1024_BITS})
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSameSaltAndLengthButDifferentPassword(Integer keyLength) {
    // When generating two consecutive keys with the same salt and length but different password
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_0123456789_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_64_BITS,
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS,
      KEY_LENGTH_512_BITS,
      KEY_LENGTH_1024_BITS})
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSamePasswordAndLengthButDifferentSalt(Integer keyLength) {
    // When generating two consecutive keys with the same password and length but different salt
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES,
            keyLength);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_64_BITS,
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS,
      KEY_LENGTH_512_BITS,
      KEY_LENGTH_1024_BITS})
  void producesTheSameKeyWhenGeneratingManyConsecutiveKeysWithTheSamePasswordSaltAndLength(Integer keyLength) {
    // Given
    final var _100 = 100;

    // When generating consecutive keys with the same password, salt and length
    final var generatedKeysSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    pbkdKeyService
                        .generateKey(
                            PASSWORD_1234567890_80_BITS,
                            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                            keyLength)
                        .getEncoded()));

    // Then all keys are the same
    assertThat(generatedKeysSet, hasSize(1));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_64_BITS,
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS,
      KEY_LENGTH_512_BITS,
      KEY_LENGTH_1024_BITS})
  void producesTheSameKeyWhenGeneratingConcurrentlyManyKeysWithTheSamePasswordSaltAndLength(Integer keyLength) throws Exception {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time keys with the same password, salt and length
    final var generatedKeysSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    pbkdKeyService.generateKey(
                        PASSWORD_1234567890_80_BITS,
                        SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                        keyLength)
                        .getEncoded()));

    // Then all keys are the same
    assertThat(generatedKeysSet, hasSize(1));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithSomeKeyLengthsAndExpectedGeneratedKey")
  void producesTheRightKeyWhenGeneratingKey(
      String password,
      byte[] salt,
      Integer keyLength,
      byte[] expectedGeneratedKey) {

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            password,
            salt,
            keyLength);

    // Then
    assertThat(generatedKey.getEncoded(), is(equalTo(expectedGeneratedKey)));
  }

  static Stream<Arguments> argumentsWithSomeKeyLengthsAndExpectedGeneratedKey() {
    return Stream.of(
        Arguments.of(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            SCRYPT_HASH_128_BITS),
        Arguments.of(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            SCRYPT_HASH_256_BITS),
        Arguments.of(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            SCRYPT_HASH_512_BITS),
        Arguments.of(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            SCRYPT_HASH_1024_BITS)
    );
  }

  @Test
  void producesTheRightKeyWhenGeneratingKeyWithSecretByteArray() {
    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            SECRET_BYTE_ARRAY_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS);

    // Then
    assertThat(
        generatedKey.getEncoded(),
        is(equalTo(
            SCRYPT_HASH_256_BITS_FOR_SECRET_BYTE_ARRAY)));
  }
}