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

import com.theicenet.cryptography.test.support.RunnerUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class RFC5054SRP6VerifierServiceTest {

  SRP6VerifierService srp6VerifierService;

  @BeforeEach
  void setUp() {
    srp6VerifierService =
        new RFC5054SRP6VerifierService(
            SRP6RFC5054TestingVectors.SG_1024,
            SRP6RFC5054TestingVectors.HASH_SHA_1);
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullSalt() {
    // Given
    final byte[] NULL_SALT = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            srp6VerifierService.generateVerifier( // When
              NULL_SALT,
              SRP6RFC5054TestingVectors.IDENTITY,
              SRP6RFC5054TestingVectors.PASSWORD));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullIdentity() {
    // Given
    final byte[] NULL_IDENTITY = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            srp6VerifierService.generateVerifier( // When
                SRP6RFC5054TestingVectors.SALT,
                NULL_IDENTITY,
                SRP6RFC5054TestingVectors.PASSWORD));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullPassword() {
    // Given
    final byte[] NULL_PASSWORD = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            srp6VerifierService.generateVerifier( // When
                SRP6RFC5054TestingVectors.SALT,
                SRP6RFC5054TestingVectors.IDENTITY,
                NULL_PASSWORD));
  }

  @Test
  void producesNotNullWhenGeneratingVerifier() {
    // When
    final var generatedVerifier =
        srp6VerifierService.generateVerifier(
            SRP6RFC5054TestingVectors.SALT,
            SRP6RFC5054TestingVectors.IDENTITY,
            SRP6RFC5054TestingVectors.PASSWORD);

    // The
    assertThat(generatedVerifier, is(notNullValue()));
  }

  @Test
  void producesTheRightVerifiedWhenGeneratingVerifier() {
    // When
    final var generatedVerifier =
        srp6VerifierService.generateVerifier(
            SRP6RFC5054TestingVectors.SALT,
            SRP6RFC5054TestingVectors.IDENTITY,
            SRP6RFC5054TestingVectors.PASSWORD);

    // The
    assertThat(
        generatedVerifier,
        is(equalTo(toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_VERIFIER))));
  }

  @Test
  void producesTheSameVerifierWhenGeneratingTwoConsecutiveVerifiersAndSameInputData() {
    // When
    final var generatedVerifier_1 =
        srp6VerifierService.generateVerifier(
            SRP6RFC5054TestingVectors.SALT,
            SRP6RFC5054TestingVectors.IDENTITY,
            SRP6RFC5054TestingVectors.PASSWORD);

    final var generatedVerifier_2 =
        srp6VerifierService.generateVerifier(
            SRP6RFC5054TestingVectors.SALT,
            SRP6RFC5054TestingVectors.IDENTITY,
            SRP6RFC5054TestingVectors.PASSWORD);

    // Then
    assertThat(generatedVerifier_1, is(equalTo(generatedVerifier_2)));
  }

  @Test
  void producesDifferentVerifierWhenGeneratingTwoConsecutiveVerifiersAndDifferentInputData() {
    // When
    final var generatedVerifier_1 =
        srp6VerifierService.generateVerifier(
            SRP6RFC5054TestingVectors.SALT,
            SRP6RFC5054TestingVectors.IDENTITY,
            SRP6RFC5054TestingVectors.PASSWORD);

    final var generatedVerifier_2 =
        srp6VerifierService.generateVerifier(
            SRP6GenericTestingVectors.SALT,
            SRP6GenericTestingVectors.IDENTITY,
            SRP6GenericTestingVectors.PASSWORD);

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
            () ->
                encodeHex(
                    srp6VerifierService.generateVerifier(
                      SRP6RFC5054TestingVectors.SALT,
                      SRP6RFC5054TestingVectors.IDENTITY,
                      SRP6RFC5054TestingVectors.PASSWORD)));

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
            () ->
                encodeHex(
                    srp6VerifierService.generateVerifier(
                        SRP6RFC5054TestingVectors.SALT,
                        SRP6RFC5054TestingVectors.IDENTITY,
                        SRP6RFC5054TestingVectors.PASSWORD)));

    // Then
    assertThat(
        generatedVerifiers.iterator().next(),
        is(equalTo(encodeHex(toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_VERIFIER)))));
  }

  @Test
  void producesTheSameVerifierWhenGeneratingConcurrentlyManyVerifiersAndSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var generatedVerifiers =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                encodeHex(
                    srp6VerifierService.generateVerifier(
                        SRP6RFC5054TestingVectors.SALT,
                        SRP6RFC5054TestingVectors.IDENTITY,
                        SRP6RFC5054TestingVectors.PASSWORD)));

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
            () ->
                encodeHex(
                    srp6VerifierService.generateVerifier(
                        SRP6RFC5054TestingVectors.SALT,
                        SRP6RFC5054TestingVectors.IDENTITY,
                        SRP6RFC5054TestingVectors.PASSWORD)));

    // Then
    assertThat(
        generatedVerifiers.iterator().next(),
        is(equalTo(encodeHex(toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_VERIFIER)))));
  }
}