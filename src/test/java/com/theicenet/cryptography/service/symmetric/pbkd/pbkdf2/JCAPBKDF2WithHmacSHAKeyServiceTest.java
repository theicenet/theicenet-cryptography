package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

class JCAPBKDF2WithHmacSHAKeyServiceTest {

  final int KEY_LENGTH_64_BITS = 64;
  final int KEY_LENGTH_128_BITS = 128;
  final int KEY_LENGTH_256_BITS = 256;
  final int KEY_LENGTH_512_BITS = 512;
  final int KEY_LENGTH_1024_BITS = 1024;
  final String RAW = "RAW";

  final String PBKDF2 = "PBKDF2";
  final String WITH_HMAC = "WithHmac";
  final String PBKDF2_WITH_HMAC = String.format("%s%s", PBKDF2, WITH_HMAC);
  final Integer _100_ITERATIONS = 100;

  final String PASSWORD_1234567890_80_BITS = "1234567890";
  final String PASSWORD_0123456789_80_BITS = "0123456789";

  final byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES =
      "ZYXWVUTSRQPONMLKJIHG".getBytes(StandardCharsets.UTF_8);

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesNotNullWhenDerivingKey(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(
      value = ShaAlgorithm.class,
      names = {"SHA3_256", "SHA3_512"},
      mode = Mode.EXCLUDE)
  void producesKeyWithRightAlgorithmWhenDerivingKeyAndSha1And2(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);
    final var PBKDF2_WITH_HMAC_ALGORITHM =
        String.format("%s%s", PBKDF2_WITH_HMAC, shaAlgorithm.toString());

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(PBKDF2_WITH_HMAC_ALGORITHM)));
  }

  @ParameterizedTest
  @EnumSource(
      value = ShaAlgorithm.class,
      names = {"SHA3_256", "SHA3_512"},
      mode = Mode.INCLUDE)
  void producesKeyWithRightAlgorithmWhenDerivingKeyAndSha3(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(PBKDF2)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesKeyWithRAWFormatWhenDerivingKey(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo(RAW)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith64Bit(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_64_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_64_BITS)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith128Bit(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_128_BITS)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith256Bit(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_256_BITS)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith512Bit(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_512_BITS)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith1024Bit(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When
    final var generatedKey =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_1024_BITS)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesTheSameKeyWhenDerivingTwoConsecutiveKeysWithTheSamePasswordSaltAndLength(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When generating two consecutive keys with the same password, salt and length
    final var generatedKey_1 =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);
    final var generatedKey_2 =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then the generated keys are the same
    assertThat(generatedKey_1.getEncoded(), is(equalTo(generatedKey_2.getEncoded())));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesDifferentKeysWhenDerivingTwoConsecutiveKeysWithTheSameSaltAndLengthButDifferentPassword(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When generating two consecutive keys with the same salt and length but different password
    final var generatedKey_1 =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);
    final var generatedKey_2 =
        aesKeyService.deriveKey(
            PASSWORD_0123456789_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesDifferentKeysWhenDerivingTwoConsecutiveKeysWithTheSamePasswordAndLengthButDifferentSalt(ShaAlgorithm shaAlgorithm) {
    // Given
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When generating two consecutive keys with the same password and length but different salt
    final var generatedKey_1 =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);
    final var generatedKey_2 =
        aesKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesTheSameKeyWhenDerivingManyConsecutiveKeysWithTheSamePasswordSaltAndLength(ShaAlgorithm shaAlgorithm) {
    // Given
    final var _100 = 100;
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When generating consecutive keys with the same password, salt and length
    final var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index ->
                aesKeyService.deriveKey(
                    PASSWORD_1234567890_80_BITS,
                    SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                    KEY_LENGTH_256_BITS))
            .map(Key::getEncoded)
            .map(BigInteger::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys are the same
    assertThat(generatedKeys, hasSize(1));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesTheSameKeyWhenDerivingConcurrentlyManyKeysWithTheSamePasswordSaltAndLength(ShaAlgorithm shaAlgorithm) throws Exception {
    // Given
    final var _500 = 500;
    final var aesKeyService = new JCAPBKDF2WithHmacSHAKeyService(shaAlgorithm, _100_ITERATIONS);

    // When generating concurrently at the same time random keys with the same password, salt and length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedKeys = new CopyOnWriteArraySet<BigInteger>();

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

              final var generatedKey =
                  aesKeyService.deriveKey(
                      PASSWORD_1234567890_80_BITS,
                      SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                      KEY_LENGTH_256_BITS);

              generatedKeys.add(new BigInteger(generatedKey.getEncoded()));
            })
        );

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all keys are the same
    assertThat(generatedKeys, hasSize(1));
  }
}