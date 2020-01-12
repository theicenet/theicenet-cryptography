package com.theicenet.cryptography.key.asymmetric.ecdsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.CombinableMatcher.both;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.hamcrest.number.OrderingComparison.greaterThanOrEqualTo;
import static org.hamcrest.number.OrderingComparison.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JCAECDSAKeyServiceTest {
  final String ECDSA = "ECDSA";
  final String X_509 = "X.509";
  final String PKCS_8 = "PKCS#8";
  final int KEY_LENGTH_160_BITS = 160;

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndInvalidKeyLength() {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECDSACurve.brainpoolpXXXr1, new SecureRandom());

    final var KEY_LENGTH_128 = 128;

    // When generating key and invalid key length
    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> {
      ecdsaKeyService.generateKey(KEY_LENGTH_128);
    });
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesNotNullKeyPairWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesNotNullPublicKeyWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesNotNullPrivateKeyWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPublicKeyWithECDSAAlgorithmWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getAlgorithm(), is(equalTo(ECDSA)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPrivateKeyWithECDSAAlgorithmWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getAlgorithm(), is(equalTo(ECDSA)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPublicKeyWithX509FormatWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getFormat(), is(equalTo(X_509)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPrivateKeyWithPKCS8FormatWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getFormat(), is(equalTo(PKCS_8)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPublicKeyWithContentWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPrivateKeyWithContentWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPublicKeyWithNonEmptyContentWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPrivateKeyWithNonEmptyContentWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPublicKeyWithTheRightBitLengthWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    final var keyFactory = KeyFactory.getInstance(ECDSA);
    final var ecPublicKeySpec = keyFactory.getKeySpec(generatedKeyPair.getPublic(), ECPublicKeySpec.class);

    assertThat(
        ecPublicKeySpec.getParams().getOrder().bitLength(),
        is(both(
            greaterThanOrEqualTo(keyLengthInBits - 15))
            .and(lessThanOrEqualTo(keyLengthInBits + 1))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesPrivateKeyWithTheRightBitLengthWhenGeneratingKey(ECDSACurve curve, Integer keyLengthInBits) throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    final var keyFactory = KeyFactory.getInstance(ECDSA);
    final var ecPrivateKeySpec = keyFactory.getKeySpec(generatedKeyPair.getPrivate(), ECPrivateKeySpec.class);

    assertThat(
        ecPrivateKeySpec.getParams().getOrder().bitLength(),
        is(both(
            greaterThanOrEqualTo(keyLengthInBits - 15))
            .and(lessThanOrEqualTo(keyLengthInBits + 1))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesDifferentPublicKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = ecdsaKeyService.generateKey(keyLengthInBits);
    final var generatedKeyPair_2 = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then the generated public keys are different
    assertThat(generatedKeyPair_1.getPublic(), is(not(equalTo(generatedKeyPair_2.getPublic()))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECDSACurveAndKeyLengthInBits")
  void producesDifferentPrivateKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength(ECDSACurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = ecdsaKeyService.generateKey(keyLengthInBits);
    final var generatedKeyPair_2 = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then the generated private keys are different
    assertThat(generatedKeyPair_1.getPrivate(), is(not(equalTo(generatedKeyPair_2.getPrivate()))));
  }

  static Stream<Arguments> argumentsWithECDSACurveAndKeyLengthInBits() {
    return Stream.of(ECDSACurve.values())
        .flatMap(curve ->
            curve.getKeyLengths().stream()
                .map(keyLength -> Arguments.of(curve, keyLength)));
  }

  @Test
  void producesDifferentPublicKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength() {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECDSACurve.brainpoolpXXXr1, new SecureRandom());

    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatePublicKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> ecdsaKeyService.generateKey(KEY_LENGTH_160_BITS))
            .map(KeyPair::getPublic)
            .collect(Collectors.toUnmodifiableSet());

    // Then all public keys have been generated and all them are different
    assertThat(generatePublicKeys, hasSize(_100));
  }

  @Test
  void producesDifferentPrivateKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength() {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECDSACurve.brainpoolpXXXr1, new SecureRandom());

    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatePrivateKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> ecdsaKeyService.generateKey(KEY_LENGTH_160_BITS))
            .map(KeyPair::getPrivate)
            .collect(Collectors.toUnmodifiableSet());

    // Then all private key have been generated and all them are different
    assertThat(generatePrivateKeys, hasSize(_100));
  }

  @Test
  void producesDifferentPublicKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECDSACurve.brainpoolpXXXr1, new SecureRandom());

    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedPublicKeys = new CopyOnWriteArraySet<PublicKey>();

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

              final var keyPair = ecdsaKeyService.generateKey(KEY_LENGTH_160_BITS);
              generatedPublicKeys.add(keyPair.getPublic());
            }));

    executorService.shutdown();
    executorService.awaitTermination(10, TimeUnit.SECONDS);

    // When generating concurrently at the same time key pairs with the same length
    assertThat(generatedPublicKeys, hasSize(_500));
  }

  @Test
  void producesDifferentPrivateKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECDSACurve.brainpoolpXXXr1, new SecureRandom());

    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedPrivateKeys = new CopyOnWriteArraySet<PrivateKey>();

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

              final var keyPair = ecdsaKeyService.generateKey(KEY_LENGTH_160_BITS);
              generatedPrivateKeys.add(keyPair.getPrivate());
            }));

    executorService.shutdown();
    executorService.awaitTermination(10, TimeUnit.SECONDS);

    // Then all private keys have been generated and all them are different
    assertThat(generatedPrivateKeys, hasSize(_500));
  }
}