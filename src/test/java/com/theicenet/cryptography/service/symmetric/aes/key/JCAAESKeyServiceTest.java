package com.theicenet.cryptography.service.symmetric.aes.key;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JCAAESKeyServiceTest {

  AESKeyService AESKeyService;

  @BeforeEach
  void setUp() {
    AESKeyService = new JCAAESKeyService();
  }

  @Test
  void producesNotNullWhenGeneratingAESKey() {
    // Given
    final var KEY_LENGTH_128_BITS = 128;

    // When generating an AES key
    var generatedKey = AESKeyService.generateAESKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesValueWithAESAlgorithmWhenGeneratingAESKey() {
    // Given
    final var KEY_LENGTH_128_BITS = 128;

    // When generating an AES key
    var generatedKey = AESKeyService.generateAESKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo("AES")));
  }

  @Test
  void producesValueWithRAWFormatWhenGeneratingAESKey() {
    // Given
    final var KEY_LENGTH_128_BITS = 128;

    // When generating an AES key
    var generatedKey = AESKeyService.generateAESKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo("RAW")));
  }

  @Test
  void producesValueWithTheRequestLengthWhenGeneratingAESKey() {
    // Given
    final var KEY_LENGTH_128_BITS = 128;

    // When generating an AES key
    var generatedKey = AESKeyService.generateAESKey(KEY_LENGTH_128_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_128_BITS)));
  }

  @Test
  void producesDifferentValuesWhenGeneratingTwoConsecutiveAESKeysWithTheSameLength() {
    // Given
    final var KEY_LENGTH_128_BITS = 128;

    // When generating two consecutive AES keys with the same length
    var generatedKey_1 = AESKeyService.generateAESKey(KEY_LENGTH_128_BITS);
    var generatedKey_2 = AESKeyService.generateAESKey(KEY_LENGTH_128_BITS);

    // Then the generated AES keys are different
    assertThat(generatedKey_1, is(not(equalTo(generatedKey_2))));
  }

  @Test
  void producesDifferentValuesWhenGeneratingManyConsecutiveAESKeysWithTheSameLength() {
    // Given
    final var KEY_LENGTH_128_BITS = 128;
    final var _100 = 100;

    // When generating consecutive AES keys with the same length
    var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> AESKeyService.generateAESKey(KEY_LENGTH_128_BITS))
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys have been generated and them all are different
    assertThat(generatedKeys, hasSize(_100));
  }

  @Test
  void producesDifferentValuesWhenGeneratingConcurrentlyManyAESKeysWithTheSameLength()
      throws InterruptedException {
    // Given
    final var KEY_LENGTH_128_BITS = 128;
    final var _500 = 500;

    // When generating concurrently at the same time random keys with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedKeys = new CopyOnWriteArraySet<SecretKey>();

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

              generatedKeys.add(AESKeyService.generateAESKey(KEY_LENGTH_128_BITS));

              synchronized (generatedKeys) {}
            }));

    executorService.awaitTermination(1, TimeUnit.SECONDS);

    // Then all keys have been generated and them all are different
    assertThat(
        generatedKeys.stream()
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_500));
  }
}
