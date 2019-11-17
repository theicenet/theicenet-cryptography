package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2.exception.JCAPBKDF2WithHmacSHAKeyException;
import com.theicenet.cryptography.test.util.HexUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.junit.jupiter.params.provider.MethodSource;

class JCAPBKDF2WithHmacSHAKeyServiceTest {

  static final int KEY_LENGTH_64_BITS = 64;
  static final int KEY_LENGTH_128_BITS = 128;
  static final int KEY_LENGTH_256_BITS = 256;
  static final int KEY_LENGTH_512_BITS = 512;
  static final int KEY_LENGTH_1024_BITS = 1024;

  final String RAW = "RAW";

  final String PBKDF2 = "PBKDF2";
  final String WITH_HMAC = "WithHmac";
  final String PBKDF2_WITH_HMAC = String.format("%s%s", PBKDF2, WITH_HMAC);

  static final Integer _100_ITERATIONS = 100;

  static final String PASSWORD_1234567890_80_BITS = "1234567890";
  final String PASSWORD_0123456789_80_BITS = "0123456789";

  static final byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES =
      "ZYXWVUTSRQPONMLKJIHG".getBytes(StandardCharsets.UTF_8);

  static final byte[] PBKDF2_WITH_HMAC_SHA1_HASH_128_BITS =
      HexUtil.decodeHex("e2e2147bd2da3dcf049e6bde51b1fea4");

  static final byte[] PBKDF2_WITH_HMAC_SHA1_HASH_256_BITS =
      HexUtil.decodeHex("e2e2147bd2da3dcf049e6bde51b1fea40bd4a3e67bb0a4c0fa75214dd0a227a5");

  static final byte[] PBKDF2_WITH_HMAC_SHA1_HASH_512_BITS =
      HexUtil.decodeHex(
          "e2e2147bd2da3dcf049e6bde51b1fea40bd4a3e67bb0a4c0f"
              + "a75214dd0a227a50848979b8698654c5f9235830d9c5af11"
              + "8912ebdd4e96d8d1059fc680982646a");

  static final byte[] PBKDF2_WITH_HMAC_SHA1_HASH_1024_BITS =
      HexUtil.decodeHex(
          "e2e2147bd2da3dcf049e6bde51b1fea40bd4a3e67bb0a4c0fa"
              + "75214dd0a227a50848979b8698654c5f9235830d9c5af11891"
              + "2ebdd4e96d8d1059fc680982646a74a13514f6b6f40ad93084"
              + "4d9bf87d651068b4609bbcd53ecee63002bfdd7a7b06fe9acd3"
              + "e84ddfeeb3936191013a316f10cdb314cc78a220b759099c13b"
              + "ab5f");

  static final byte[] PBKDF2_WITH_HMAC_SHA256_HASH_128_BITS =
      HexUtil.decodeHex("f0e0abdc00625bc7f11f4480f4d5e334");

  static final byte[] PBKDF2_WITH_HMAC_SHA256_HASH_256_BITS =
      HexUtil.decodeHex("f0e0abdc00625bc7f11f4480f4d5e3347eea018027420fdf9d2aa0cfa5fef65b");

  static final byte[] PBKDF2_WITH_HMAC_SHA256_HASH_512_BITS =
      HexUtil.decodeHex(
          "f0e0abdc00625bc7f11f4480f4d5e3347eea018027420fdf9d2aa"
              + "0cfa5fef65b55f5db5101727f1d81bdfb4a67c49a14126144df9e"
              + "bf0041deaf95a92d56e7a2");

  static final byte[] PBKDF2_WITH_HMAC_SHA256_HASH_1024_BITS =
      HexUtil.decodeHex(
          "f0e0abdc00625bc7f11f4480f4d5e3347eea018027420fdf9d2aa0c"
              + "fa5fef65b55f5db5101727f1d81bdfb4a67c49a14126144df9ebf00"
              + "41deaf95a92d56e7a29e852d66a4696a997517ef624ec090b0b78d5"
              + "e07e955a1679332c160deb689b87d8128d97f48c06bb38c84328519"
              + "10332e3b8a5a946ad4315fa6d6c68dd9cff0");

  static final byte[] PBKDF2_WITH_HMAC_SHA512_HASH_128_BITS =
      HexUtil.decodeHex("8f5c08c9d6d4051b5797c6add3179f11");

  static final byte[] PBKDF2_WITH_HMAC_SHA512_HASH_256_BITS =
      HexUtil.decodeHex("8f5c08c9d6d4051b5797c6add3179f11716afd1db9010cadcae4c5b6ee4a43e7");

  static final byte[] PBKDF2_WITH_HMAC_SHA512_HASH_512_BITS =
      HexUtil.decodeHex(
          "8f5c08c9d6d4051b5797c6add3179f11716afd1db9010cadcae4c5b6e"
              + "e4a43e704fa224ff3841adcc3648b919b2691c939c5248947a9aacd0"
              + "a889eef537e7887");

  static final byte[] PBKDF2_WITH_HMAC_SHA512_HASH_1024_BITS =
      HexUtil.decodeHex(
          "8f5c08c9d6d4051b5797c6add3179f11716afd1db9010cadcae4c5b6ee4"
              + "a43e704fa224ff3841adcc3648b919b2691c939c5248947a9aacd0a889"
              + "eef537e7887c0bb0e4c2a55b1839f6b929063f5b76a5e2d8305cfb00f6"
              + "87228eb203a45d201b680abf971751407b1c319fdda125b81f0a1feb72"
              + "afdd985d4665963f9a43e9d");

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNullPassword(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    final String NULL_PASSWORD = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                NULL_PASSWORD,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_128_BITS));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNullSalt(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    final byte[] NULL_SALT = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                NULL_SALT,
                KEY_LENGTH_128_BITS));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNegativeKeyLength(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    final var KEY_LENGTH_MINUS_ONE = -1;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_MINUS_ONE));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndZeroKeyLength(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    final var KEY_LENGTH_ZERO = 0;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_ZERO));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void throwsJCAPBKDF2WithHmacSHAKeyExceptionWhenGeneratingKeyAndException(ShaAlgorithm shaAlgorithm) {
    // Given
    final var MINUS_ONE_ITERATIONS = -1;
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                MINUS_ONE_ITERATIONS));

    // Then
    assertThrows(
        JCAPBKDF2WithHmacSHAKeyException.class,
        () ->
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_128_BITS));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesNotNullWhenGeneratingKey(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
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
  void producesKeyWithRightAlgorithmWhenGeneratingKeyAndSha1And2(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    final var PBKDF2_WITH_HMAC_ALGORITHM =
        String.format("%s%s", PBKDF2_WITH_HMAC, shaAlgorithm.toString());

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
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
  void producesKeyWithRightAlgorithmWhenGeneratingKeyAndSha3(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(PBKDF2)));
  }

  @ParameterizedTest
  @EnumSource(ShaAlgorithm.class)
  void producesKeyWithRAWFormatWhenGeneratingKey(ShaAlgorithm shaAlgorithm) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo(RAW)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllShaAlgorithmAndMultipleKeyLengths")
  void producesKeyWithTheRequestLengthWhenGeneratingKey(ShaAlgorithm shaAlgorithm, Integer keyLength) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(keyLength)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllShaAlgorithmAndMultipleKeyLengths")
  void producesTheSameKeyWhenGeneratingTwoConsecutiveKeysWithTheSamePasswordSaltAndLength(ShaAlgorithm shaAlgorithm, Integer keyLength) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When generating two consecutive keys with the same password, salt and length
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then the generated keys are the same
    assertThat(generatedKey_1.getEncoded(), is(equalTo(generatedKey_2.getEncoded())));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllShaAlgorithmAndMultipleKeyLengths")
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSameSaltAndLengthButDifferentPassword(ShaAlgorithm shaAlgorithm, Integer keyLength) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When generating two consecutive keys with the same salt and length but different password
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_0123456789_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllShaAlgorithmAndMultipleKeyLengths")
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSamePasswordAndLengthButDifferentSalt(ShaAlgorithm shaAlgorithm, Integer keyLength) {
    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When generating two consecutive keys with the same password and length but different salt
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES,
            keyLength);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllShaAlgorithmAndMultipleKeyLengths")
  void producesTheSameKeyWhenGeneratingManyConsecutiveKeysWithTheSamePasswordSaltAndLength(ShaAlgorithm shaAlgorithm, Integer keyLength) {
    // Given
    final var _100 = 100;
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When generating consecutive keys with the same password, salt and length
    final var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index ->
                pbkdKeyService.generateKey(
                    PASSWORD_1234567890_80_BITS,
                    SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                    keyLength))
            .map(Key::getEncoded)
            .map(BigInteger::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys are the same
    assertThat(generatedKeys, hasSize(1));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllShaAlgorithmAndMultipleKeyLengths")
  void producesTheSameKeyWhenGeneratingConcurrentlyManyKeysWithTheSamePasswordSaltAndLength(ShaAlgorithm shaAlgorithm, Integer keyLength) throws Exception {
    // Given
    final var _500 = 500;
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                _100_ITERATIONS));

    // When generating concurrently at the same time keys with the same password, salt and length
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
                  pbkdKeyService.generateKey(
                      PASSWORD_1234567890_80_BITS,
                      SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                      keyLength);

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

  static Stream<Arguments> argumentsWithAllShaAlgorithmAndMultipleKeyLengths() {
    return Stream
        .of(ShaAlgorithm.values())
        .flatMap(shaAlgorithm ->
            Stream
                .of(
                    KEY_LENGTH_64_BITS,
                    KEY_LENGTH_128_BITS,
                    KEY_LENGTH_256_BITS,
                    KEY_LENGTH_512_BITS,
                    KEY_LENGTH_1024_BITS)
                .map(keyLength -> Arguments.of(shaAlgorithm, keyLength)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllShaAlgorithmAndMultipleKeyLengthsAndExpectedGeneratedKey")
  void producesTheRightKeyWhenGeneratingKey(
      ShaAlgorithm shaAlgorithm,
      String password,
      byte[] salt,
      Integer keyLength,
      Integer iterations,
      byte[] expectedGeneratedKey) {

    // Given
    final var pbkdKeyService =
        new JCAPBKDF2WithHmacSHAKeyService(
            new PBKDF2Configuration(
                shaAlgorithm,
                iterations));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            password,
            salt,
            keyLength);

    // Then
    assertThat(generatedKey.getEncoded(), is(equalTo(expectedGeneratedKey)));
  }

  static Stream<Arguments> argumentsWithAllShaAlgorithmAndMultipleKeyLengthsAndExpectedGeneratedKey() {
    return Stream.of(
        Arguments.of(
            ShaAlgorithm.SHA1,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA1_HASH_128_BITS),
        Arguments.of(
            ShaAlgorithm.SHA1,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA1_HASH_256_BITS),
        Arguments.of(
            ShaAlgorithm.SHA1,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA1_HASH_512_BITS),
        Arguments.of(
            ShaAlgorithm.SHA1,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA1_HASH_1024_BITS),
        Arguments.of(
            ShaAlgorithm.SHA256,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA256_HASH_128_BITS),
        Arguments.of(
            ShaAlgorithm.SHA256,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA256_HASH_256_BITS),
        Arguments.of(
            ShaAlgorithm.SHA256,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA256_HASH_512_BITS),
        Arguments.of(
            ShaAlgorithm.SHA256,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA256_HASH_1024_BITS),
        Arguments.of(
            ShaAlgorithm.SHA512,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA512_HASH_128_BITS),
        Arguments.of(
            ShaAlgorithm.SHA512,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA512_HASH_256_BITS),
        Arguments.of(
            ShaAlgorithm.SHA512,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA512_HASH_512_BITS),
        Arguments.of(
            ShaAlgorithm.SHA512,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            _100_ITERATIONS,
            PBKDF2_WITH_HMAC_SHA512_HASH_1024_BITS)
    );
  }
}