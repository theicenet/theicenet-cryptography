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
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.N;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.b;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.g;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class SRP6ServerUtilTest {

  @Test
  void throwsNullPointerExceptionWhenComputingBAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeB(NULL_N, g, EXPECTED_K, EXPECTED_VERIFIER, b)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingBAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeB(N, NULL_G, EXPECTED_K, EXPECTED_VERIFIER, b)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingBAndNullK() {
    // Given
    final BigInteger NULL_K = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeB(N, g, NULL_K, EXPECTED_VERIFIER, b)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingBAndNullVerifierV() {
    // Given
    final BigInteger NULL_VERIFIER = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeB(N, g, EXPECTED_K, NULL_VERIFIER, b)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingBAndNullPrivateValueB() {
    // Given
    final BigInteger NULL_PRIVATE_VALUE_B = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeB(N, g, EXPECTED_K, EXPECTED_VERIFIER, NULL_PRIVATE_VALUE_B)); // When
  }

  @Test
  void producesNotNullWhenWhenComputingB() {
    // When
    final var computedB = SRP6ServerUtil.computeB(N, g, EXPECTED_K, EXPECTED_VERIFIER, b);

    // Then
    assertThat(computedB, is(notNullValue()));
  }

  @Test
  void producesTheRightResultWhenWhenComputingB() {
    // When
    final var computedB = SRP6ServerUtil.computeB(N, g, EXPECTED_K, EXPECTED_VERIFIER, b);

    // Then
    assertThat(computedB, is(equalTo(EXPECTED_B)));
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeS(NULL_N, EXPECTED_VERIFIER, EXPECTED_U, b, EXPECTED_A)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullVerifierV() {
    // Given
    final BigInteger NULL_VERIFIER = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeS(N, NULL_VERIFIER, EXPECTED_U, b, EXPECTED_A)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullU() {
    // Given
    final BigInteger NULL_U = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeS(N, EXPECTED_VERIFIER, NULL_U, b, EXPECTED_A)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullPrivateValueB() {
    // Given
    final BigInteger NULL_PRIVATE_VALUE_B = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeS(N, EXPECTED_VERIFIER, EXPECTED_U, NULL_PRIVATE_VALUE_B, EXPECTED_A)); // When
  }

  @Test
  void throwsNullPointerExceptionWhenComputingSAndNullPublicValueA() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_A = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> SRP6ServerUtil.computeS(N, EXPECTED_VERIFIER, EXPECTED_U, b, NULL_PUBLIC_VALUE_A)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndInvalidPublicValueA() {
    // Given
    final BigInteger INVALID_PUBLIC_VALUE_A = N.multiply(BigInteger.TEN);

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6ServerUtil.computeS(N, EXPECTED_VERIFIER, EXPECTED_U, b, INVALID_PUBLIC_VALUE_A)); // When
  }

  @Test
  void producesNotNullWhenComputingS() {
    // When
    final var computedS =
        SRP6ServerUtil.computeS(N, EXPECTED_VERIFIER, EXPECTED_U, b, EXPECTED_A);

    // Then
    assertThat(computedS, is(notNullValue()));
  }

  @Test
  void producesTheRightResultWhenComputingS() {
    // When
    final var computedS =
        SRP6ServerUtil.computeS(N, EXPECTED_VERIFIER, EXPECTED_U, b, EXPECTED_A);

    // Then
    assertThat(computedS, is(equalTo(EXPECTED_S)));
  }
}