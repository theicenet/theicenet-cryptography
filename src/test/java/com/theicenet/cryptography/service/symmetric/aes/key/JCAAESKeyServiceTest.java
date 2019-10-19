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

  final Integer KEY_LENGTH_128_BITS = 128;

  AESKeyService aesKeyService;

  @BeforeEach
  void setUp() {
    aesKeyService = new JCAAESKeyService();
  }

  @Test
  void producesNotNullWhenGeneratingAESKey() {
    // When generating an AES key
    var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesKeyWithAESAlgorithmWhenGeneratingAESKey() {
    // When generating an AES key
    var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo("AES")));
  }

  @Test
  void producesKeyWithRAWFormatWhenGeneratingAESKey() {
    // When generating an AES key
    var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo("RAW")));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenGeneratingAESKey() {
    // When generating an AES key
    var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_128_BITS)));
  }

  @Test
  void producesDifferentKeysWhenGeneratingTwoConsecutiveAESKeysWithTheSameLength() {
    // When generating two consecutive AES keys with the same length
    var generatedKey_1 = aesKeyService.generateKey(KEY_LENGTH_128_BITS);
    var generatedKey_2 = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then the generated AES keys are different
    assertThat(generatedKey_1, is(not(equalTo(generatedKey_2))));
  }

  @Test
  void producesDifferentKeysWhenGeneratingManyConsecutiveAESKeysWithTheSameLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive AES keys with the same length
    var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> aesKeyService.generateKey(KEY_LENGTH_128_BITS))
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys have been generated and them all are different
    assertThat(generatedKeys, hasSize(_100));
  }

  @Test
  void producesDifferentKeysWhenGeneratingConcurrentlyManyAESKeysWithTheSameLength()
      throws InterruptedException {
    // Given
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

              generatedKeys.add(aesKeyService.generateKey(KEY_LENGTH_128_BITS));
            }));

    executorService.awaitTermination(1, TimeUnit.SECONDS);

    // Then all keys have been generated and them all are different
    assertThat(generatedKeys, hasSize(_500));
  }
}
