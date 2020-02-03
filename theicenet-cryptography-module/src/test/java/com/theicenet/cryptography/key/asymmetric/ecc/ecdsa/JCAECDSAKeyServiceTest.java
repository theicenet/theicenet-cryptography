package com.theicenet.cryptography.key.asymmetric.ecc.ecdsa;

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
import com.theicenet.cryptography.key.asymmetric.ecc.ECCCurve;
import com.theicenet.cryptography.key.asymmetric.ecc.ECCKeyAlgorithm;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JCAECDSAKeyServiceTest {
  final ECCKeyAlgorithm ECDSA = ECCKeyAlgorithm.ECDSA;
  final String X_509 = "X.509";
  final String PKCS_8 = "PKCS#8";
  final int KEY_LENGTH_160_BITS = 160;

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndInvalidKeyLength() {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var KEY_LENGTH_128 = 128;

    // When generating key and invalid key length
    // Then throws IllegalArgumentException
    assertThrows(
        IllegalArgumentException.class,
        () -> ecdsaKeyService.generateKey(KEY_LENGTH_128));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesNotNullKeyPairWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesNotNullPublicKeyWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesNotNullPrivateKeyWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithECDSAAlgorithmWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getAlgorithm(), is(equalTo(ECDSA.toString())));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithECDSAAlgorithmWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getAlgorithm(), is(equalTo(ECDSA.toString())));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithX509FormatWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getFormat(), is(equalTo(X_509)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithPKCS8FormatWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getFormat(), is(equalTo(PKCS_8)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithNonEmptyContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithNonEmptyContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithTheRightBitLengthWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    final var keyFactory = KeyFactory.getInstance(ECDSA.toString());
    final var ecPublicKeySpec = keyFactory.getKeySpec(generatedKeyPair.getPublic(), ECPublicKeySpec.class);

    assertThat(
        ecPublicKeySpec.getParams().getOrder().bitLength(),
        is(both(
            greaterThanOrEqualTo(keyLengthInBits - 15))
            .and(lessThanOrEqualTo(keyLengthInBits + 1))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithTheRightBitLengthWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then
    final var keyFactory = KeyFactory.getInstance(ECDSA.toString());
    final var ecPrivateKeySpec = keyFactory.getKeySpec(generatedKeyPair.getPrivate(), ECPrivateKeySpec.class);

    assertThat(
        ecPrivateKeySpec.getParams().getOrder().bitLength(),
        is(both(
            greaterThanOrEqualTo(keyLengthInBits - 15))
            .and(lessThanOrEqualTo(keyLengthInBits + 1))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesDifferentPublicKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = ecdsaKeyService.generateKey(keyLengthInBits);
    final var generatedKeyPair_2 = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then the generated public keys are different
    assertThat(
        generatedKeyPair_1.getPublic().getEncoded(),
        is(not(equalTo(
            generatedKeyPair_2.getPublic().getEncoded()))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesDifferentPrivateKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(curve, new SecureRandom());

    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = ecdsaKeyService.generateKey(keyLengthInBits);
    final var generatedKeyPair_2 = ecdsaKeyService.generateKey(keyLengthInBits);

    // Then the generated private keys are different
    assertThat(
        generatedKeyPair_1.getPrivate().getEncoded(),
        is(not(equalTo(
            generatedKeyPair_2.getPrivate().getEncoded()))));
  }

  static Stream<Arguments> argumentsWithECCCurveAndKeyLengthInBits() {
    return Stream.of(ECCCurve.values())
        .flatMap(curve ->
            curve.getKeyLengths().stream()
                .map(keyLength -> Arguments.of(curve, keyLength)));
  }

  @Test
  void producesDifferentPublicKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength() {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatedPublicKeysSet =
        RunnerUtil.runConsecutively(
            _100,
            () ->
                HexUtil.encodeHex(
                    ecdsaKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPublic()
                        .getEncoded()));

    // Then all public keys have been generated and all them are different
    assertThat(generatedPublicKeysSet, hasSize(_100));
  }

  @Test
  void producesDifferentPrivateKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength() {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatedPrivateKeysSet =
        RunnerUtil.runConsecutively(
            _100,
            () ->
                HexUtil.encodeHex(
                    ecdsaKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPrivate()
                        .getEncoded()));

    // Then all private key have been generated and all them are different
    assertThat(generatedPrivateKeysSet, hasSize(_100));
  }

  @Test
  void producesDifferentPublicKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var generatedPublicKeysSet =
        RunnerUtil.runConcurrently(
            _500,
            () ->
                HexUtil.encodeHex(
                    ecdsaKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPublic()
                        .getEncoded()));

    // When generating concurrently at the same time key pairs with the same length
    assertThat(generatedPublicKeysSet, hasSize(_500));
  }

  @Test
  void producesDifferentPrivateKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() throws Exception {
    // Given
    final AsymmetricKeyService ecdsaKeyService =
        new JCAECDSAKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var generatedPrivateKeysSet =
        RunnerUtil.runConcurrently(
            _500,
            () ->
                HexUtil.encodeHex(
                    ecdsaKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPrivate()
                        .getEncoded()));

    // Then all private keys have been generated and all them are different
    assertThat(generatedPrivateKeysSet, hasSize(_500));
  }
}