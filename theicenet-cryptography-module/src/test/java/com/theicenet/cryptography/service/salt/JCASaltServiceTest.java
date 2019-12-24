package com.theicenet.cryptography.service.salt;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;

import java.security.SecureRandom;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JCASaltServiceTest {
  final int SALT_LENGTH_16_BYTES = 16;
  final int SALT_LENGTH_32_BYTES = 32;
  final int SALT_LENGTH_64_BYTES = 64;
  final int SALT_LENGTH_128_BYTES = 128;

  SaltService saltService;

  @BeforeEach
  void setUp() {
    saltService = new JCASaltService(new SecureRandom());
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
    final var generatedSalts =
        IntStream
            .range(0, _100)
            .mapToObj(index -> saltService.generateRandom(saltLength))
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all Salts have been generated and all them are different
    assertThat(generatedSalts, hasSize(_100));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      SALT_LENGTH_16_BYTES,
      SALT_LENGTH_32_BYTES,
      SALT_LENGTH_64_BYTES,
      SALT_LENGTH_128_BYTES})
  void producesDifferentSaltsWhenGeneratingConcurrentlyManyRandomsWithTheSameLength(int saltLength)
      throws InterruptedException {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random Salts with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedSalts = new CopyOnWriteArraySet<byte[]>();

    IntStream
        .range(0, _500)
        .forEach(index ->
            executorService.execute(() -> {
              countDownLatch.countDown();
              try {
                countDownLatch.await();
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
              }

              generatedSalts.add(saltService.generateRandom(saltLength));
            }));

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all Salts have been generated and all them are different
    assertThat(
        generatedSalts.stream()
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_500));
  }
}