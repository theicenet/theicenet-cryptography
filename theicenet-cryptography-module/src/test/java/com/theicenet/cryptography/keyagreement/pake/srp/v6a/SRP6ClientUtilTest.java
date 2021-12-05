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
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_X;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.HASH_SHA_256;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.IDENTITY;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.N;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.PASSWORD;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.SALT;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.a;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.g;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
  void throwsNullPointerExceptionWhenGeneratingVerifierAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
      NullPointerException.class,
        () -> SRP6ClientUtil.generateVerifier(NULL_N, g, EXPECTED_X)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenGeneratingVerifierAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.generateVerifier(N, NULL_G, EXPECTED_X)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenGeneratingVerifierAndNullX() {
    // Given
    final BigInteger NULL_X = null;

    // Then
    assertThrows(
        NullPointerException.class,
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
  void throwsNullPointerExceptionWhenComputingXAndNullDigest() {
    // Given
    final DigestService NULL_DIGGEST_SERVICE = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeX(NULL_DIGGEST_SERVICE, SALT, IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingXAndNullSalt() {
    // Given
    final byte[] NULL_SALT = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeX(sha256Digest, NULL_SALT, IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingXAndNullIdentity() {
    // Given
    final byte[] NULL_IDENTITY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeX(sha256Digest, SALT, NULL_IDENTITY, PASSWORD)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingXAndNullPassword() {
    // Given
    final byte[] NULL_PASSWORD = null;

    // Then
    assertThrows(
        NullPointerException.class,
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
  void throwsNullPointerExceptionWhenComputingAAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeA(NULL_N, g, a)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingAAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeA(N, NULL_G, a)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingAAndNullPrivateValueA() {
    // Given
    final BigInteger NULL_PRIVATE_VALUE_A = null;

    // Then
    assertThrows(
        NullPointerException.class,
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
  void throwsNullPointerExceptionWhenComputingSAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeS(NULL_N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeS(N, NULL_G, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullK() {
    // Given
    final BigInteger NULL_K = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeS(N, g, NULL_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullX() {
    // Given
    final BigInteger NULL_X = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, NULL_X, EXPECTED_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullU() {
    // Given
    final BigInteger NULL_U = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, NULL_U, a, EXPECTED_B)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullPrivateValueA() {
    // Given
    final BigInteger NULL_PRIVATE_VALUE_A = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, NULL_PRIVATE_VALUE_A, EXPECTED_B)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullPublicValueB() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_B = null;

    // Then
    assertThrows(
        NullPointerException.class,
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