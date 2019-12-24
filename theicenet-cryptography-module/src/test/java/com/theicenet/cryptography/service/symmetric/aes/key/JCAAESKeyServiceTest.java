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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JCAAESKeyServiceTest {

  final int KEY_LENGTH_128_BITS = 128;
  final int KEY_LENGTH_256_BITS = 256;
  final String AES = "AES";
  final String RAW = "RAW";

  AESKeyService aesKeyService;

  @BeforeEach
  void setUp() {
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

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS})
  void producesKeyWithTheRequestLengthWhenGeneratingKey(int keyLength) {
    // When
    final var generatedKey = aesKeyService.generateKey(keyLength);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(keyLength)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS})
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength(int keyLength) {
    // When generating two consecutive keys with the same length
    final var generatedKey_1 = aesKeyService.generateKey(keyLength);
    final var generatedKey_2 = aesKeyService.generateKey(keyLength);

    // Then the generated keys are different
    assertThat(generatedKey_1, is(not(equalTo(generatedKey_2))));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS})
  void producesDifferentKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength(int keyLength) {
    // Given
    final var _100 = 100;

    // When generating consecutive keys with the same length
    final var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> aesKeyService.generateKey(keyLength))
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys have been generated and all them are different
    assertThat(generatedKeys, hasSize(_100));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS})
  void producesDifferentKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength(int keyLength) throws Exception {
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

              generatedKeys.add(aesKeyService.generateKey(keyLength));
            }));

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all keys have been generated and all them are different
    assertThat(generatedKeys, hasSize(_500));
  }
}
