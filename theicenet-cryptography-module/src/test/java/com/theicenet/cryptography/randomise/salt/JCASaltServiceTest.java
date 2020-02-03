package com.theicenet.cryptography.randomise.salt;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.randomise.RandomiseService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JCASaltServiceTest {
  final int SALT_LENGTH_16_BYTES = 16;
  final int SALT_LENGTH_32_BYTES = 32;
  final int SALT_LENGTH_64_BYTES = 64;
  final int SALT_LENGTH_128_BYTES = 128;

  RandomiseService saltService;

  @BeforeEach
  void setUp() {
    saltService = new JCASaltService(new SecureRandom());
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingRandomAndInvalidSaltLength() {
    // Given
    final var SALT_LENGTH_MINUS_ONE = -1;

    // When generating salt and invalid salt length
    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> {
      saltService.generateRandom(SALT_LENGTH_MINUS_ONE);
    });
  }

  @Test
  void producesNotNullWhenGeneratingRandom() {
    // When
    final var generatedSalt = saltService.generateRandom(SALT_LENGTH_16_BYTES);

    // Then
    assertThat(generatedSalt, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenGeneratingRandom() {
    // When
    final var generatedSalt = saltService.generateRandom(SALT_LENGTH_16_BYTES);

    // Then
    assertThat(generatedSalt.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      SALT_LENGTH_16_BYTES,
      SALT_LENGTH_32_BYTES,
      SALT_LENGTH_64_BYTES,
      SALT_LENGTH_128_BYTES})
  void producesSaltWithTheRequestedLengthWhenGeneratingRandom(int saltLength) {
    // When
    final var generatedSalt = saltService.generateRandom(saltLength);

    // Then
    assertThat(generatedSalt.length, is(equalTo(saltLength)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      SALT_LENGTH_16_BYTES,
      SALT_LENGTH_32_BYTES,
      SALT_LENGTH_64_BYTES,
      SALT_LENGTH_128_BYTES})
  void producesDifferentSaltsWhenGeneratingTwoConsecutiveRandomsWithTheSameLength(int saltLength) {
    // When generating two consecutive random Salts with the same length
    final var generatedSalt_1 = saltService.generateRandom(saltLength);
    final var generatedSalt_2 = saltService.generateRandom(saltLength);

    // Then the generated random Salts are different
    assertThat(generatedSalt_1, is(not(equalTo(generatedSalt_2))));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      SALT_LENGTH_16_BYTES,
      SALT_LENGTH_32_BYTES,
      SALT_LENGTH_64_BYTES,
      SALT_LENGTH_128_BYTES})
  void producesDifferentSaltsWhenGeneratingManyConsecutiveRandomsWithTheSameLength(int saltLength) {
    // Given
    final var _100 = 100;

    // When generating consecutive random Salts with the same length
    final var generatedSaltsSet =
        RunnerUtil.runConsecutively(
            _100,
            () -> HexUtil.encodeHex(saltService.generateRandom(saltLength)));

    // Then all Salts have been generated and all them are different
    assertThat(generatedSaltsSet, hasSize(_100));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      SALT_LENGTH_16_BYTES,
      SALT_LENGTH_32_BYTES,
      SALT_LENGTH_64_BYTES,
      SALT_LENGTH_128_BYTES})
  void producesDifferentSaltsWhenGeneratingConcurrentlyManyRandomsWithTheSameLength(int saltLength) {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random Salts with the same length
    final var generatedSaltsSet =
        RunnerUtil.runConcurrently(
            _500,
            () ->
                HexUtil.encodeHex(
                    saltService.generateRandom(saltLength)));

    // Then all Salts have been generated and all them are different
    assertThat(generatedSaltsSet, hasSize(_500));
  }
}