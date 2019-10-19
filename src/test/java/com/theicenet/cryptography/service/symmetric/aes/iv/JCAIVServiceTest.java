package com.theicenet.cryptography.service.symmetric.aes.iv;

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
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JCAIVServiceTest {

  final int IV_LENGTH_16_BYTES = 16;

  IVService ivService;

  @BeforeEach
  void setUp() {
    ivService = new JCAIVService(new SecureRandom());
  }

  @Test
  void producesNotNullWhenGeneratingRandomIV() {
    // When generating a random IV
    var generatedKey = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenGeneratingRandomIV() {
    // When generating a random IV
    var generatedKey = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then
    assertThat(generatedKey.length, is(greaterThan(0)));
  }

  @Test
  void producesIVWithTheRequestLengthWhenGeneratingRandomIV() {
    // When generating a random IV
    var generatedKey = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then
    assertThat(generatedKey.length, is(equalTo(IV_LENGTH_16_BYTES)));
  }

  @Test
  void producesDifferentIVsWhenGeneratingTwoConsecutiveRandomIVsWithTheSameLength() {
    // When generating two consecutive random IVs with the same length
    var generatedKey_1 = ivService.generateRandom(IV_LENGTH_16_BYTES);
    var generatedKey_2 = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then the generated random IVs are different
    assertThat(generatedKey_1, is(not(equalTo(generatedKey_2))));
  }

  @Test
  void producesDifferentIVsWhenGeneratingManyConsecutiveRandomIVsWithTheSameLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive random IVs with the same length
    var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> ivService.generateRandom(IV_LENGTH_16_BYTES))
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all IVs have been generated and them all are different
    assertThat(generatedKeys, hasSize(_100));
  }

  @Test
  void producesDifferentIVsWhenGeneratingConcurrentlyManyRandomIVsWithTheSameLength()
      throws InterruptedException {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random IVs with the same length
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

              generatedKeys.add(ivService.generateRandom(IV_LENGTH_16_BYTES));
            }));

    executorService.awaitTermination(1, TimeUnit.SECONDS);

    // Then all IVs have been generated and them all are different
    assertThat(
        generatedKeys.stream()
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_500));
  }
}