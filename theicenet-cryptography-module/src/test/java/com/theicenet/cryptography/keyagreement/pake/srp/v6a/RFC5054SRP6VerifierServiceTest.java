/*
 * Copyright 2019-2021 the original author or authors.
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
package com.theicenet.cryptography.keyagreement.pake.srp.v6a;

import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.ByteArraysUtil.toUnsignedByteArray;
import static com.theicenet.cryptography.test.support.HexUtil.encodeHex;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.test.support.RunnerUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class RFC5054SRP6VerifierServiceTest {

  final SRP6StandardGroup SG_2048 = SRP6GenericTestingVectors.SG_2048;
  final DigestAlgorithm HASH_SHA_256 = SRP6GenericTestingVectors.HASH_SHA_256;

  final byte[] IDENTITY = SRP6GenericTestingVectors.IDENTITY;
  final byte[] PASSWORD = SRP6GenericTestingVectors.PASSWORD;

  final byte[] SALT = SRP6GenericTestingVectors.SALT;

  final byte[] VERIFIER = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_VERIFIER);

  SRP6VerifierService srp6VerifierService;

  @BeforeEach
  void setUp() {
    srp6VerifierService = new RFC5054SRP6VerifierService(SG_2048, HASH_SHA_256);
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullSalt() {
    // Given
    final byte[] NULL_SALT = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6VerifierService.generateVerifier(NULL_SALT, IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullIdentity() {
    // Given
    final byte[] NULL_IDENTITY = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6VerifierService.generateVerifier(SALT, NULL_IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullPassword() {
    // Given
    final byte[] NULL_PASSWORD = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6VerifierService.generateVerifier(SALT, IDENTITY, NULL_PASSWORD)); // When
  }

  @Test
  void producesNotNullWhenGeneratingVerifier() {
    // When
    final var generatedVerifier =
        srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD);

    // The
    assertThat(generatedVerifier, is(notNullValue()));
  }

  @Test
  void producesTheRightVerifiedWhenGeneratingVerifier() {
    // When
    final var generatedVerifier =
        srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD);

    // The
    assertThat(generatedVerifier, is(equalTo(VERIFIER)));
  }

  @Test
  void producesTheSameVerifierWhenGeneratingTwoConsecutiveVerifiersAndSameInputData() {
    // When
    final var generatedVerifier_1 =
        srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD);

    final var generatedVerifier_2 =
        srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD);

    // Then
    assertThat(generatedVerifier_1, is(equalTo(generatedVerifier_2)));
  }

  @Test
  void producesDifferentVerifierWhenGeneratingTwoConsecutiveVerifiersAndDifferentInputData() {
    // When
    final var generatedVerifier_1 =
        srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD);

    final var generatedVerifier_2 =
        srp6VerifierService.generateVerifier(
            SRP6RFC5054TestingVectors.SALT,
            SRP6RFC5054TestingVectors.IDENTITY,
            SRP6RFC5054TestingVectors.PASSWORD);

    // Then
    assertThat(generatedVerifier_1, is(not(equalTo(generatedVerifier_2))));
  }

  @Test
  void producesTheSameVerifierWhenGeneratingManyConsecutiveVerifiersAndSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var generatedVerifiers =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD)));

    // Then
    assertThat(generatedVerifiers, hasSize(1));
  }

  @Test
  void producesTheRightVerifierWhenGeneratingManyConsecutiveVerifiersAndSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var generatedVerifiers =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD)));

    // Then
    assertThat(generatedVerifiers.iterator().next(), is(equalTo(encodeHex(VERIFIER))));
  }

  @Test
  void producesTheSameVerifierWhenGeneratingConcurrentlyManyVerifiersAndSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var generatedVerifiers =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD)));

    // Then
    assertThat(generatedVerifiers, hasSize(1));
  }

  @Test
  void producesTheRightVerifierWhenGeneratingConcurrentlyManyVerifiersAndSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var generatedVerifiers =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD)));

    // Then
    assertThat(generatedVerifiers.iterator().next(), is(equalTo(encodeHex(VERIFIER))));
  }
}