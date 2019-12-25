package com.theicenet.cryptography.service.symmetric.aes.iv;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

class JCAIVServiceTest {

  final int IV_LENGTH_16_BYTES = 16;
  final int IV_LENGTH_32_BYTES = 32;

  IVService ivService;

  @BeforeEach
  void setUp() {
    ivService = new JCAIVService(new SecureRandom());
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingRandomAndInvalidIVLength() {
    // Given
    final var IV_LENGTH_MINUS_ONE = -1;

    // When generating IV and invalid IV length
    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> {
      ivService.generateRandom(IV_LENGTH_MINUS_ONE);
    });
  }

  @Test
  void producesNotNullWhenGeneratingRandom() {
    // When
    final var generatedIV = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then
    assertThat(generatedIV, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenGeneratingRandom() {
    // When
    final var generatedIV = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then
    assertThat(generatedIV.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      IV_LENGTH_16_BYTES,
      IV_LENGTH_32_BYTES})
  void producesIVWithTheRequestLengthWhenGeneratingRandom(int ivLength) {
    // When
    final var generatedIV = ivService.generateRandom(ivLength);

    // Then
    assertThat(generatedIV.length, is(equalTo(ivLength)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      IV_LENGTH_16_BYTES,
      IV_LENGTH_32_BYTES})
  void producesDifferentIVsWhenGeneratingTwoConsecutiveRandomsWithTheSameLength(int ivLength) {
    // When generating two consecutive random IVs with the same length
    final var generatedIV_1 = ivService.generateRandom(ivLength);
    final var generatedIV_2 = ivService.generateRandom(ivLength);

    // Then the generated random IVs are different
    assertThat(generatedIV_1, is(not(equalTo(generatedIV_2))));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      IV_LENGTH_16_BYTES,
      IV_LENGTH_32_BYTES})
  void producesDifferentIVsWhenGeneratingManyConsecutiveRandomsWithTheSameLength(int ivLength) {
    // Given
    final var _100 = 100;

    // When generating consecutive random IVs with the same length
    final var generatedIVs =
        IntStream
            .range(0, _100)
            .mapToObj(index -> ivService.generateRandom(ivLength))
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all IVs have been generated and all them are different
    assertThat(generatedIVs, hasSize(_100));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      IV_LENGTH_16_BYTES,
      IV_LENGTH_32_BYTES})
  void producesDifferentIVsWhenGeneratingConcurrentlyManyRandomsWithTheSameLength(int ivLength)
      throws InterruptedException {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random IVs with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedIVs = new CopyOnWriteArraySet<byte[]>();

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

              generatedIVs.add(ivService.generateRandom(ivLength));
            }));

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all IVs have been generated and all them are different
    assertThat(
        generatedIVs.stream()
            .map(String::new)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_500));
  }
}