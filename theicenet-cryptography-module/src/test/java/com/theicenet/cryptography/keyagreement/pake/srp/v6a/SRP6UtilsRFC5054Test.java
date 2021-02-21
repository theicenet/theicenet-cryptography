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

import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.EXPECTED_A;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.EXPECTED_B;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.EXPECTED_K;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.EXPECTED_S;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.EXPECTED_U;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.EXPECTED_VERIFIER;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.EXPECTED_X;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.HASH_SHA_1;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.IDENTITY;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.N;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.PASSWORD;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.SALT;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.a;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.b;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6RFC5054TestingVectors.g;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import org.junit.jupiter.api.Test;

/**
 * Testing scenario uses the test vectors described in RFC 5054 specification, Appendix B
 *
 * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
 *
 * The purpose of this test is to prove that the utils implementation fully comply with the
 * RFC 5054 specification by checking the implementation works as decribed in the specification
 * when using the RFC 5054 testing vectors
 *
 * Please note that the RFC 5054 Appendix B doesn't provide with any expected values for M1, M2 and
 * Session Key. For this reason this this test doesn't test doesn't provide with any test to
 * validate M1, M2 and Session Key are properly computed. This test fully stick to the specific
 * test vectors provided by RFC 5054 specification, Appendix B
 *
 * @author Juan Fidalgo
 */
class SRP6UtilsRFC5054Test {

  final DigestService digestService = new JCADigestService(HASH_SHA_1);

  @Test
  void computesTheRightK() {
    // When
    final var computedK =
        SRP6CommonUtil.computeK(digestService, N, g);

    // Then
    assertThat(computedK, is(equalTo(EXPECTED_K)));
  }

  @Test
  void computesTheRightX() {
    // When
    final var computedX =
        SRP6ClientUtil.computeX(digestService, SALT, IDENTITY, PASSWORD);

    // Then
    assertThat(computedX, is(equalTo(EXPECTED_X)));
  }

  @Test
  void computesTheRightVerifier() {
    // Given
    final var computedX =
        SRP6ClientUtil.computeX(digestService, SALT, IDENTITY, PASSWORD);

    // When
    final var generateVerifier =
        SRP6ClientUtil.generateVerifier(N, g, computedX);

    // Then
    assertThat(generateVerifier, is(equalTo(EXPECTED_VERIFIER)));
  }

  @Test
  void computesTheRightA() {
    // When
    final var computedA = SRP6ClientUtil.computeA(N, g, a);

    // Then
    assertThat(computedA, is(equalTo(EXPECTED_A)));
  }

  @Test
  void computesTheRightB() {
    // When
    final var computedB =
        SRP6ServerUtil.computeB(N, g, EXPECTED_K, EXPECTED_VERIFIER, b);

    // Then
    assertThat(computedB, is(equalTo(EXPECTED_B)));
  }

  @Test
  void computesTheRightU() {
    // When
    final var computedU =
        SRP6CommonUtil.computeU(digestService, N, EXPECTED_A, EXPECTED_B);

    // Then
    assertThat(computedU, is(equalTo(EXPECTED_U)));
  }

  @Test
  void computesTheRightClientS() {
    // When
    final var computedClientS =
        SRP6ClientUtil.computeS(N, g, EXPECTED_K, EXPECTED_X, EXPECTED_U, a, EXPECTED_B);

    // Then
    assertThat(computedClientS, is(equalTo(EXPECTED_S)));
  }

  @Test
  void computesTheRightServerS() {
    // When
    final var computedServerS =
        SRP6ServerUtil.computeS(N, EXPECTED_VERIFIER, EXPECTED_U, b, EXPECTED_A);

    // Then
    assertThat(computedServerS, is(equalTo(EXPECTED_S)));
  }
}