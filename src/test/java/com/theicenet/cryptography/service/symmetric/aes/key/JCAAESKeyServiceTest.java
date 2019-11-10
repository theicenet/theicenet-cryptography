package com.theicenet.cryptography.service.symmetric.aes.key;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import java.security.SecureRandom;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JCAAESKeyServiceTest {

  final Integer KEY_LENGTH_128_BITS = 128;
  final Integer KEY_LENGTH_256_BITS = 256;
  final String AES = "AES";
  final String RAW = "RAW";

  AESKeyService aesKeyService;

  @BeforeEach
  void setUp() {
    // This test can't use a mock for SecureRandom. It needs to use a real one.
    aesKeyService = new JCAAESKeyService(new SecureRandom());
  }

  @Test
  void producesNotNullWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesKeyWithAESAlgorithmWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(AES)));
  }

  @Test
  void producesKeyWithRAWFormatWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo(RAW)));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenGeneratingKeyWith128Bit() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_128_BITS)));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenGeneratingKeyWith256Bit() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_256_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_256_BITS)));
  }

  @Test
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength() {
    // When generating two consecutive keys with the same length
    final var generatedKey_1 = aesKeyService.generateKey(KEY_LENGTH_128_BITS);
    final var generatedKey_2 = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then the generated keys are different
    assertThat(generatedKey_1, is(not(equalTo(generatedKey_2))));
  }

  @Test
  void producesDifferentKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive keys with the same length
    final var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> aesKeyService.generateKey(KEY_LENGTH_128_BITS))
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys have been generated and all them are different
    assertThat(generatedKeys, hasSize(_100));
  }

  @Test
  void producesDifferentKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() throws Exception {
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

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all keys have been generated and all them are different
    assertThat(generatedKeys, hasSize(_500));
  }
}
