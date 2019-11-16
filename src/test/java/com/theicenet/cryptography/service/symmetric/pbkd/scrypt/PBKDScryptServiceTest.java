package com.theicenet.cryptography.service.symmetric.pbkd.scrypt;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.service.symmetric.pbkd.PBKDKeyService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PBKDScryptServiceTest {

  final int KEY_LENGTH_64_BITS = 64;
  final int KEY_LENGTH_128_BITS = 128;
  final int KEY_LENGTH_256_BITS = 256;
  final int KEY_LENGTH_512_BITS = 512;
  final int KEY_LENGTH_1024_BITS = 1024;

  final String RAW = "RAW";

  final String SCRYPT = "SCrypt";

  final int CPU_MEMORY_COST_1024 = 1024;
  final int BLOCK_SIZE_8 = 8;
  final int PARALLELIZATION = 1;

  final String PASSWORD_1234567890_80_BITS = "1234567890";
  final String PASSWORD_0123456789_80_BITS = "0123456789";

  final byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES =
      "ZYXWVUTSRQPONMLKJIHG".getBytes(StandardCharsets.UTF_8);

  PBKDKeyService pbkdKeyService;

  @BeforeEach
  void setUp() {
    pbkdKeyService = new PBKDScryptService(CPU_MEMORY_COST_1024, BLOCK_SIZE_8, PARALLELIZATION);
  }

  @Test
  void producesNotNullWhenDerivingKey() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesKeyWithRightAlgorithmWhenDerivingKey() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(SCRYPT)));
  }

  @Test
  void producesKeyWithRAWFormatWhenDerivingKey() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo(RAW)));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith64Bit() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_64_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_64_BITS)));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith128Bit() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_128_BITS)));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith256Bit() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_256_BITS)));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith512Bit() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_512_BITS)));
  }

  @Test
  void producesKeyWithTheRequestLengthWhenDerivingKeyWith1024Bit() {
    // When
    final var generatedKey =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(KEY_LENGTH_1024_BITS)));
  }

  @Test
  void producesTheSameKeyWhenDerivingTwoConsecutiveKeysWithTheSamePasswordSaltAndLength() {
    // When generating two consecutive keys with the same password, salt and length
    final var generatedKey_1 =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);
    final var generatedKey_2 =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then the generated keys are the same
    assertThat(generatedKey_1.getEncoded(), is(equalTo(generatedKey_2.getEncoded())));
  }

  @Test
  void producesDifferentKeysWhenDerivingTwoConsecutiveKeysWithTheSameSaltAndLengthButDifferentPassword() {
    // When generating two consecutive keys with the same salt and length but different password
    final var generatedKey_1 =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);
    final var generatedKey_2 =
        pbkdKeyService.deriveKey(
            PASSWORD_0123456789_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @Test
  void producesDifferentKeysWhenDerivingTwoConsecutiveKeysWithTheSamePasswordAndLengthButDifferentSalt() {
    // When generating two consecutive keys with the same password and length but different salt
    final var generatedKey_1 =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);
    final var generatedKey_2 =
        pbkdKeyService.deriveKey(
            PASSWORD_1234567890_80_BITS,
            SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @Test
  void producesTheSameKeyWhenDerivingManyConsecutiveKeysWithTheSamePasswordSaltAndLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive keys with the same password, salt and length
    final var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index ->
                pbkdKeyService.deriveKey(
                    PASSWORD_1234567890_80_BITS,
                    SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                    KEY_LENGTH_256_BITS))
            .map(Key::getEncoded)
            .map(BigInteger::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys are the same
    assertThat(generatedKeys, hasSize(1));
  }

  @Test
  void producesTheSameKeyWhenDerivingConcurrentlyManyKeysWithTheSamePasswordSaltAndLength() throws Exception {
    // Given
    final var _500 = 500;

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
                  pbkdKeyService.deriveKey(
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