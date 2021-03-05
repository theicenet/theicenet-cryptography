/*
 * Copyright 2019-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.theicenet.cryptography.key.asymmetric.ecc.ecdh;

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

/**
 * @author Juan Fidalgo
 */
class JCAECDHKeyServiceTest {
  final ECCKeyAlgorithm ECDH = ECCKeyAlgorithm.ECDH;
  final String X_509 = "X.509";
  final String PKCS_8 = "PKCS#8";
  final int KEY_LENGTH_160_BITS = 160;

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndInvalidKeyLength() {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var KEY_LENGTH_128 = 128;

    // Then throws IllegalArgumentException
    assertThrows(
        IllegalArgumentException.class,
        () -> ecdhKeyService.generateKey(KEY_LENGTH_128)); // When generating key and invalid key length
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesNotNullKeyPairWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesNotNullPublicKeyWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesNotNullPrivateKeyWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithECDHAlgorithmWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getAlgorithm(), is(equalTo(ECDH.toString())));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithECDHAlgorithmWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getAlgorithm(), is(equalTo(ECDH.toString())));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithX509FormatWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getFormat(), is(equalTo(X_509)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithPKCS8FormatWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getFormat(), is(equalTo(PKCS_8)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithNonEmptyContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPrivateKeyWithNonEmptyContentWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithECCCurveAndKeyLengthInBits")
  void producesPublicKeyWithTheRightBitLengthWhenGeneratingKey(ECCCurve curve, Integer keyLengthInBits) throws Exception {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    final var keyFactory = KeyFactory.getInstance(ECDH.toString());
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
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When
    final var generatedKeyPair = ecdhKeyService.generateKey(keyLengthInBits);

    // Then
    final var keyFactory = KeyFactory.getInstance(ECDH.toString());
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
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = ecdhKeyService.generateKey(keyLengthInBits);
    final var generatedKeyPair_2 = ecdhKeyService.generateKey(keyLengthInBits);

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
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(curve, new SecureRandom());

    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = ecdhKeyService.generateKey(keyLengthInBits);
    final var generatedKeyPair_2 = ecdhKeyService.generateKey(keyLengthInBits);

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
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatedPublicKeysSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    ecdhKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPublic()
                        .getEncoded()));

    // Then all public keys have been generated and all them are different
    assertThat(generatedPublicKeysSet, hasSize(_100));
  }

  @Test
  void producesDifferentPrivateKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength() {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatedPrivateKeysSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    ecdhKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPrivate()
                        .getEncoded()));

    // Then all private key have been generated and all them are different
    assertThat(generatedPrivateKeysSet, hasSize(_100));
  }

  @Test
  void producesDifferentPublicKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var generatedPublicKeysSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    ecdhKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPublic()
                        .getEncoded()));

    // When generating concurrently at the same time key pairs with the same length
    assertThat(generatedPublicKeysSet, hasSize(_500));
  }

  @Test
  void producesDifferentPrivateKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() throws Exception {
    // Given
    final AsymmetricKeyService ecdhKeyService =
        new JCAECDHKeyService(ECCCurve.brainpoolpXXXr1, new SecureRandom());

    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var generatedPrivateKeysSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    ecdhKeyService
                        .generateKey(KEY_LENGTH_160_BITS)
                        .getPrivate()
                        .getEncoded()));

    // Then all private keys have been generated and all them are different
    assertThat(generatedPrivateKeysSet, hasSize(_500));
  }
}