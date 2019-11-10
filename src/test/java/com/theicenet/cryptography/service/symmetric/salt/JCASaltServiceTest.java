package com.theicenet.cryptography.service.symmetric.salt;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;

import com.theicenet.cryptography.service.symmetric.salt.JCASaltService;
import com.theicenet.cryptography.service.symmetric.salt.SaltService;
import java.security.SecureRandom;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JCASaltServiceTest {
  final int SALT_LENGTH_16_BYTES = 16;
  final int SALT_LENGTH_32_BYTES = 32;

  SaltService saltService;

  @BeforeEach
  void setUp() {
    saltService = new JCASaltService(new SecureRandom());
  }

  @Test
  void producesNotNullWhenGeneratingRandom() {
    // When
    final var generatedKey = saltService.generateRandom(SALT_LENGTH_16_BYTES);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenGeneratingRandom() {
    // When
    final var generatedKey = saltService.generateRandom(SALT_LENGTH_16_BYTES);

    // Then
    assertThat(generatedKey.length, is(greaterThan(0)));
  }

  @Test
  void producesSaltWithTheRequestLengthWhenGeneratingRandomWith16Bytes() {
    // When
    final var generatedKey = saltService.generateRandom(SALT_LENGTH_16_BYTES);

    // Then
    assertThat(generatedKey.length, is(equalTo(SALT_LENGTH_16_BYTES)));
  }

  @Test
  void producesSaltWithTheRequestLengthWhenGeneratingRandomWith32Bytes() {
    // When
    final var generatedKey = saltService.generateRandom(SALT_LENGTH_32_BYTES);

    // Then
    assertThat(generatedKey.length, is(equalTo(SALT_LENGTH_32_BYTES)));
  }

  @Test
  void producesDifferentSaltsWhenGeneratingTwoConsecutiveRandomsWithTheSameLength() {
    // When generating two consecutive random Salts with the same length
    final var generatedKey_1 = saltService.generateRandom(SALT_LENGTH_16_BYTES);
    final var generatedKey_2 = saltService.generateRandom(SALT_LENGTH_16_BYTES);

    // Then the generated random Salts are different
    assertThat(generatedKey_1, is(not(equalTo(generatedKey_2))));
  }

  @Test
  void producesDifferentSaltsWhenGeneratingManyConsecutiveRandomsWithTheSameLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive random Salts with the same length
    final var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> saltService.generateRandom(SALT_LENGTH_16_BYTES))
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all Salts have been generated and all them are different
    assertThat(generatedKeys, hasSize(_100));
  }

  @Test
  void producesDifferentSaltsWhenGeneratingConcurrentlyManyRandomsWithTheSameLength()
      throws InterruptedException {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random Salts with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedKeys = new CopyOnWriteArraySet<byte[]>();

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

              generatedKeys.add(saltService.generateRandom(SALT_LENGTH_16_BYTES));
            }));

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all Salts have been generated and all them are different
    assertThat(
        generatedKeys.stream()
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_500));
  }
}