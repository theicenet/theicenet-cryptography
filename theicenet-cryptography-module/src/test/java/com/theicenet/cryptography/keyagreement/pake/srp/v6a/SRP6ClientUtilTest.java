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

import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_A;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_B;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_K;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_S;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_U;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_VERIFIER;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.HASH_SHA_256;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.IDENTITY;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.N;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.PASSWORD;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.SALT;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.a;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.g;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_X;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.*;

import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class SRP6ClientUtilTest {

  final DigestService sha256Digest = new JCADigestService(HASH_SHA_256);

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
      IllegalArgumentException.class,
        () -> SRP6ClientUtil.generateVerifier(NULL_N, g, EXPECTED_X)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.generateVerifier(N, NULL_G, EXPECTED_X)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingVerifierAndNullX() {
    // Given
    final BigInteger NULL_X = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.generateVerifier(N, g, NULL_X)); // When
  }

  @Test
  void producesNotNullWhenGeneratingVerifier() {
    // When
    final var generatedVerifier = SRP6ClientUtil.generateVerifier(N, g, EXPECTED_X);

    // Then
    assertThat(generatedVerifier, is(notNullValue()));
  }

  @Test
  void producesTheRightResultWhenGeneratingVerifier() {
    // When
    final var generatedVerifier = SRP6ClientUtil.generateVerifier(N, g, EXPECTED_X);

    // Then
    assertThat(generatedVerifier, is(equalTo(EXPECTED_VERIFIER)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingXAndNullDigest() {
    // Given
    final DigestService NULL_DIGGEST_SERVICE = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeX(NULL_DIGGEST_SERVICE, SALT, IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingXAndNullSalt() {
    // Given
    final byte[] NULL_SALT = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeX(sha256Digest, NULL_SALT, IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingXAndNullIdentity() {
    // Given
    final byte[] NULL_IDENTITY = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeX(sha256Digest, SALT, NULL_IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingXAndNullPassword() {
    // Given
    final byte[] NULL_PASSWORD = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeX(sha256Digest, SALT, IDENTITY, NULL_PASSWORD)); // When
  }

  @Test
  void producesNotNullWhenComputingX() {
    // When
    final var computedX = SRP6ClientUtil.computeX(sha256Digest, SALT, IDENTITY, PASSWORD);

    // Then
    assertThat(computedX, is(notNullValue()));
  }

  @Test
  void producesTheRightResultWhenComputingX() {
    // When
    final var computedX = SRP6ClientUtil.computeX(sha256Digest, SALT, IDENTITY, PASSWORD);

    // Then
    assertThat(computedX, is(equalTo(EXPECTED_X)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingAAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeA(NULL_N, g, a)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingAAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeA(N, NULL_G, a)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingAAndNullPrivateValueA() {
    // Given
    final BigInteger NULL_PRIVATE_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeA(N, g, NULL_PRIVATE_VALUE_A)); // When
  }

  @Test
  void producesNotNullWhenComputingA() {
    // When
    final var computedA = SRP6ClientUtil.computeA(N, g, a);

    // Then
    assertThat(computedA, is(notNullValue()));
  }

  @Test
  void producesTheRightResultNullWhenComputingA() {
    // When
    final var computedA = SRP6ClientUtil.computeA(N, g, a);

    // Then
    assertThat(computedA, is(equalTo(EXPECTED_A)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(NULL_N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(N, NULL_G, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullK() {
    // Given
    final BigInteger NULL_K = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(N, g, NULL_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullX() {
    // Given
    final BigInteger NULL_X = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, NULL_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullU() {
    // Given
    final BigInteger NULL_U = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, NULL_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullPrivateValueA() {
    // Given
    final BigInteger NULL_PRIVATE_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, NULL_PRIVATE_VALUE_A, EXPECTED_B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullPublicValueB() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_B = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, NULL_PUBLIC_VALUE_B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndInvalidPublicValueB() {
    // Given
    final BigInteger INVALID_PUBLIC_VALUE_B = N.multiply(BigInteger.TEN);

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, INVALID_PUBLIC_VALUE_B)); // When
  }

  @Test
  void producesNotNullWhenComputingS() {
    // When
    final var computedS =
        SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B);

    // Then
    assertThat(computedS, is(notNullValue()));
  }

  @Test
  void producesTheRightValueWhenComputingS() {
    // When
    final var computedS =
        SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B);

    // Then
    assertThat(computedS, is(equalTo(EXPECTED_S)));
  }
}