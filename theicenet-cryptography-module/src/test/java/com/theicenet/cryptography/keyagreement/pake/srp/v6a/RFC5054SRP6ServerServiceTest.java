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

import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.ByteArraysUtil.toBigInteger;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.ByteArraysUtil.toUnsignedByteArray;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.computeK;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ServerUtil.computeB;
import static com.theicenet.cryptography.test.support.HexUtil.encodeHex;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.keyagreement.SRP6ServerService;
import com.theicenet.cryptography.random.JCASecureRandomDataService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class RFC5054SRP6ServerServiceTest {

  final SRP6StandardGroup SG_2048 = SRP6GenericTestingVectors.SG_2048;
  final DigestAlgorithm HASH_SHA_256 = SRP6GenericTestingVectors.HASH_SHA_256;

  final BigInteger N = SG_2048.getN();
  final BigInteger g = SG_2048.getG();

  final byte[] VERIFIER = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_VERIFIER);

  final byte[] A = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_A);
  final byte[] b = toUnsignedByteArray(SRP6GenericTestingVectors.b);
  final byte[] B = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_B);
  final byte[] S = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_S);
  final byte[] M1 = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_M1);
  final byte[] M2 = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_M2);

  final byte[] SESSION_KEY = toUnsignedByteArray(SRP6GenericTestingVectors.EXPECTED_SESSION_KEY);

  SRP6ServerService srp6ServerService;

  @BeforeEach
  void setUp() {
    srp6ServerService =
        new RFC5054SRP6ServerService(
            SG_2048,
            HASH_SHA_256,
            new JCASecureRandomDataService(new SecureRandom()));
  }

  @Test
  void producesNotNullWhenComputingValuesB() {
    // When
    final var computedValuesB = srp6ServerService.computeValuesB(VERIFIER);

    // Then
    assertThat(computedValuesB, is(notNullValue()));
  }

  @Test
  void producesNotNullClientPrivateValueWhenComputingValuesB() {
    // When
    final var computedValuesB = srp6ServerService.computeValuesB(VERIFIER);

    // Then
    assertThat(computedValuesB.getServerPrivateValueB(), is(notNullValue()));
  }

  @Test
  void producesNotNullClientPublicValueWhenComputingValuesB() {
    // When
    final var computedValuesB = srp6ServerService.computeValuesB(VERIFIER);

    // Then
    assertThat(computedValuesB.getServerPublicValueB(), is(notNullValue()));
  }

  @Test
  void producesTheRightValueWhenComputingValuesB() {
    // When
    final var computedValuesB = srp6ServerService.computeValuesB(VERIFIER);

    // Then
    final byte[] EXPECTED_SERVER_PUBLIC_VALUE_B =
        toUnsignedByteArray(
            computeB(
                N,
                g,
                computeK(new JCADigestService(HASH_SHA_256), N, g),
                toBigInteger(VERIFIER),
                toBigInteger(computedValuesB.getServerPrivateValueB())));

    assertThat(computedValuesB.getServerPublicValueB(), is(equalTo(EXPECTED_SERVER_PUBLIC_VALUE_B)));
  }

  @Test
  void producesDifferentValuesWhenComputingTwoConsecutiveValuesBAndSameVerifier() {
    // When
    final var computedValuesB_1 = srp6ServerService.computeValuesB(VERIFIER);
    final var computedValuesB_2 = srp6ServerService.computeValuesB(VERIFIER);

    // Then
    assertThat(computedValuesB_1, is(not(samePropertyValuesAs(computedValuesB_2))));
  }

  @Test
  void producesDifferentValuesWhenComputingManyConsecutiveValuesBAndSameVerifier() {
    // Given
    final var _100 = 100;

    // When
    final var computedValuesBs =
        RunnerUtil.runConsecutivelyToList(
            _100,
            () -> srp6ServerService.computeValuesB(VERIFIER));

    // Then
    assertThat(
        computedValuesBs.stream()
            .map(SRP6ServerValuesB::getServerPrivateValueB)
            .map(HexUtil::encodeHex)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_100));

    assertThat(
        computedValuesBs.stream()
            .map(SRP6ServerValuesB::getServerPublicValueB)
            .map(HexUtil::encodeHex)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_100));
  }

  @Test
  void producesTheRightValueWhenComputingManyConsecutiveValuesBAndSameVerifier() {
    // Given
    final var _100 = 100;

    // When
    final var computedValuesBs =
        RunnerUtil.runConsecutivelyToList(
            _100,
            () -> srp6ServerService.computeValuesB(VERIFIER));

    // Then
    computedValuesBs.forEach(computedValuesB -> {
      final byte[] EXPECTED_SERVER_PUBLIC_VALUE_B =
          toUnsignedByteArray(
              computeB(
                  N,
                  g,
                  computeK(new JCADigestService(HASH_SHA_256), N, g),
                  toBigInteger(VERIFIER),
                  toBigInteger(computedValuesB.getServerPrivateValueB())));

      assertThat(
          computedValuesB.getServerPublicValueB(),
          is(equalTo(EXPECTED_SERVER_PUBLIC_VALUE_B)));
    });
  }

  @Test
  void producesDifferentValuesWhenComputingConcurrentlyManyValuesBAndSameVerifier() {
    // Given
    final var _500 = 500;

    // When
    final var computedValuesBs =
        RunnerUtil.runConcurrentlyToList(
            _500,
            () -> srp6ServerService.computeValuesB(VERIFIER));

    // Then
    assertThat(
        computedValuesBs.stream()
            .map(SRP6ServerValuesB::getServerPrivateValueB)
            .map(HexUtil::encodeHex)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_500));

    assertThat(
        computedValuesBs.stream()
            .map(SRP6ServerValuesB::getServerPublicValueB)
            .map(HexUtil::encodeHex)
            .collect(Collectors.toUnmodifiableSet()),
        hasSize(_500));
  }

  @Test
  void producesTheRightValueWhenComputingConcurrentlyManyValuesB() {
    // Given
    final var _500 = 500;

    // When
    final var computedValuesBs =
        RunnerUtil.runConcurrentlyToList(
            _500,
            () -> srp6ServerService.computeValuesB(VERIFIER));

    // Then
    computedValuesBs.forEach(computedValuesB -> {
      final byte[] EXPECTED_CLIENT_PUBLIC_VALUE =
          toUnsignedByteArray(
              computeB(
                  N,
                  g,
                  computeK(new JCADigestService(HASH_SHA_256), N, g),
                  toBigInteger(VERIFIER),
                  toBigInteger(computedValuesB.getServerPrivateValueB())));

      assertThat(computedValuesB.getServerPublicValueB(), is(equalTo(EXPECTED_CLIENT_PUBLIC_VALUE)));
    });
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullVerifier() {
    // Given
    final byte[] NULL_VERIFIER = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeS(NULL_VERIFIER, A, b, B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullClientPublicValueA() {
    // Given
    final byte[] NULL_CLIENT_PUBLIC_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeS(VERIFIER, NULL_CLIENT_PUBLIC_VALUE_A, b, B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullServerPrivateValueB() {
    // Given
    final byte[] NULL_SERVER_PRIVATE_VALUE_B = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeS(VERIFIER, A, NULL_SERVER_PRIVATE_VALUE_B, B)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSAndNullServerPublicValueB() {
    // Given
    final byte[] NULL_SERVER_PUBLIC_VALUE_B = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeS(VERIFIER, A, b, NULL_SERVER_PUBLIC_VALUE_B)); // When
  }
  
  @Test
  void producesNotNullWhenComputingS() {
    // When
    final var computedS = srp6ServerService.computeS(VERIFIER, A, b, B);

    // Then
    assertThat(computedS, is(notNullValue()));
  }

  @Test
  void producesTheRightValueWhenComputingS() {
    // When
    final var computedS = srp6ServerService.computeS(VERIFIER, A, b, B);

    // Then
    assertThat(computedS, is(equalTo(S)));
  }

  @Test
  void producesTheSameValueWhenComputingTwoConsecutiveSAndTheSameInputData() {
    // When
    final var computedS_1 = srp6ServerService.computeS(VERIFIER, A, b, B);
    final var computedS_2 = srp6ServerService.computeS(VERIFIER, A, b, B);

    // Then
    assertThat(computedS_1, is(equalTo(computedS_2)));
  }

  @Test
  void producesDifferentValuesWhenComputingTwoConsecutiveSAndDifferentInputData() {
    // When
    final var computedS_1 = srp6ServerService.computeS(VERIFIER, A, b, B);

    final var computedS_2 =
        srp6ServerService.computeS(
            toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_VERIFIER),
            toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_A),
            toUnsignedByteArray(SRP6RFC5054TestingVectors.b),
            toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_B));

    // Then
    assertThat(computedS_1, is(not(equalTo(computedS_2))));
  }

  @Test
  void producesTheSameValueWhenComputingManyConsecutiveSAndTheSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var computedSs =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6ServerService.computeS(VERIFIER, A, b, B)));

    // Then
    assertThat(computedSs, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenComputingManyConsecutiveSAndTheSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var computedSs =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6ServerService.computeS(VERIFIER, A, b, B)));

    // Then
    assertThat(computedSs.iterator().next(), is(equalTo(encodeHex(S))));
  }

  @Test
  void producesTheSameValueWhenComputingConcurrentlyManySAndTheSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var computedSs =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6ServerService.computeS(VERIFIER, A, b, B)));

    // Then
    assertThat(computedSs, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenComputingConcurrentlyManySAndTheSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var computedSs =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6ServerService.computeS(VERIFIER, A, b, B)));

    // Then
    assertThat(computedSs.iterator().next(), is(equalTo(encodeHex(S))));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenValidatingReceivedM1AndNullClientPublicValueA() {
    // Given
    final byte[] NULL_CLIENT_PUBLIC_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.isValidReceivedM1(NULL_CLIENT_PUBLIC_VALUE_A, B, S, M1)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenValidatingReceivedM1AndNullServerPublicValueB() {
    // Given
    final byte[] NULL_SERVER_PUBLIC_VALUE_B = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.isValidReceivedM1(A, NULL_SERVER_PUBLIC_VALUE_B, S, M1)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenValidatingReceivedM1AndNullS() {
    // Given
    final byte[] NULL_S = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.isValidReceivedM1(A, B, NULL_S, M1)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenValidatingReceivedM1AndNullM1() {
    // Given
    final byte[] NULL_M1 = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.isValidReceivedM1(A, B, S, NULL_M1)); // When
  }

  @Test
  void producesTheRightValueWhenValidatingReceivedM1AndValidM1() {
    // When
    final var isValidReceivedM1 = srp6ServerService.isValidReceivedM1(A, B, S, M1);

    // Then
    assertThat(isValidReceivedM1, is(true));
  }

  @Test
  void producesTheRightValueWhenValidatingReceivedM1AndInvalidM1() {
    // Given
    final var INVALID_RECEIVED_M1 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    // When
    final var isValidReceivedM1 =
        srp6ServerService.isValidReceivedM1(A, B, S, INVALID_RECEIVED_M1);

    // Then
    assertThat(isValidReceivedM1, is(false));
  }

  @Test
  void producesTheSameValueWhenValidatingTwoReceivedM1AndValidM1() {
    // When
    final var isValidReceivedM1_1 = srp6ServerService.isValidReceivedM1(A, B, S, M1);
    final var isValidReceivedM1_2 = srp6ServerService.isValidReceivedM1(A, B, S, M1);

    // Then
    assertThat(isValidReceivedM1_1, is(equalTo(isValidReceivedM1_2)));
  }

  @Test
  void producesTheSameValueWhenValidatingTwoReceivedM1AndInvalidM1() {
    // Given
    final var INVALID_RECEIVED_M1 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    // When
    final var isValidReceivedM1_1 =
        srp6ServerService.isValidReceivedM1(A, B, S, INVALID_RECEIVED_M1);

    final var isValidReceivedM1_2 =
        srp6ServerService.isValidReceivedM1(A, B, S, INVALID_RECEIVED_M1);

    // Then
    assertThat(isValidReceivedM1_1, is(equalTo(isValidReceivedM1_2)));
  }

  @Test
  void producesTheSameValueWhenValidatingManyConsecutiveReceivedM1AndValidM1() {
    // Given
    final var _100 = 100;

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, M1));

    // Then
    assertThat(isValidReceivedM1s, hasSize(1));
  }

  @Test
  void producesTheSameValueWhenValidatingManyConsecutiveReceivedM1AndInvalidM1() {
    // Given
    final var _100 = 100;
    final var INVALID_RECEIVED_M1 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, INVALID_RECEIVED_M1));

    // Then
    assertThat(isValidReceivedM1s, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenValidatingManyConsecutiveReceivedM1AndValidM1() {
    // Given
    final var _100 = 100;

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, M1));

    // Then
    assertThat(isValidReceivedM1s.iterator().next(), is(true));
  }

  @Test
  void producesTheRightValueWhenValidatingManyConsecutiveReceivedM1AndInvalidM1() {
    // Given
    final var _100 = 100;
    final var INVALID_RECEIVED_M1 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, INVALID_RECEIVED_M1));

    // Then
    assertThat(isValidReceivedM1s.iterator().next(), is(false));
  }

  @Test
  void producesTheSameValueWhenValidatingConcurrentlyManyReceivedM1AndValidM1() {
    // Given
    final var _500 = 500;

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, M1));

    // Then
    assertThat(isValidReceivedM1s, hasSize(1));
  }

  @Test
  void producesTheSameValueWhenValidatingConcurrentlyManyReceivedM1AndInvalidM1() {
    // Given
    final var _500 = 500;
    final var INVALID_RECEIVED_M1 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, INVALID_RECEIVED_M1));

    // Then
    assertThat(isValidReceivedM1s, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenValidatingConcurrentlyManyReceivedM1AndValidM1() {
    // Given
    final var _500 = 500;

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, M1));

    // Then
    assertThat(isValidReceivedM1s.iterator().next(), is(true));
  }

  @Test
  void producesTheRightValueWhenValidatingConcurrentlyManyReceivedM1AndInvalidM1() {
    // Given
    final var _500 = 500;
    final var INVALID_RECEIVED_M1 = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    // When
    final var isValidReceivedM1s =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> srp6ServerService.isValidReceivedM1(A, B, S, INVALID_RECEIVED_M1));

    // Then
    assertThat(isValidReceivedM1s.iterator().next(), is(false));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingM2AndNullClientPublicValueA() {
    // Given
    final byte[] NULL_CLIENT_PUBLIC_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeM2(NULL_CLIENT_PUBLIC_VALUE_A, S, M1));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingM2AndNullS() {
    // Given
    final byte[] NULL_S = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeM2(A, NULL_S, M1)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingM2AndNullM1() {
    // Given
    final byte[] NULL_M1 = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeM2(A, S, NULL_M1)); // When
  }

  @Test
  void producesNotNullWhenComputingM2() {
    // When
    final var computedM2 = srp6ServerService.computeM2(A, S, M1);

    // Then
    assertThat(computedM2, is(notNullValue()));
  }

  @Test
  void producesTheRightValueWhenComputingM2() {
    // When
    final var computedM2 = srp6ServerService.computeM2(A, S, M1);

    // Then
    assertThat(computedM2, is(equalTo(M2)));
  }

  @Test
  void producesTheSameValueWhenComputingTwoConsecutiveM2AndTheSameInputData() {
    // When
    final var computedM2_1 = srp6ServerService.computeM2(A, S, M1);
    final var computedM2_2 = srp6ServerService.computeM2(A, S, M1);

    // Then
    assertThat(computedM2_1, is(equalTo(computedM2_2)));
  }

  @Test
  void producesDifferentValuesWhenComputingTwoConsecutiveM2AndDifferentInputData() {
    // When
    final var computedM2_1 = srp6ServerService.computeM2(A, S, M1);
    final var computedM2_2 =
        srp6ServerService.computeM2(
            toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_A),
            toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_S),
            M1);

    // Then
    assertThat(computedM2_1, is(not(equalTo(computedM2_2))));
  }

  @Test
  void producesTheSameValueWhenComputingManyConsecutiveM2AndTheSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var computedM2s =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6ServerService.computeM2(A, S, M1)));

    // Then
    assertThat(computedM2s, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenComputingManyConsecutiveM2AndTheSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var computedM2s =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6ServerService.computeM2(A, S, M1)));

    // Then
    assertThat(computedM2s.iterator().next(), is(equalTo(encodeHex(M2))));
  }

  @Test
  void producesTheSameValueWhenComputingConcurrentlyManyM2AndTheSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var computedM2s =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6ServerService.computeM2(A, S, M1)));

    // Then
    assertThat(computedM2s, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenComputingConcurrentlyManyM2AndTheSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var computedM2s =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6ServerService.computeM2(A, S, M1)));

    // Then
    assertThat(computedM2s.iterator().next(), is(equalTo(encodeHex(M2))));
  }
  
  @Test
  void throwsIllegalArgumentExceptionWhenComputingSessionKeyAndNullS() {
    // Given
    final byte[] NULL_S = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> srp6ServerService.computeSessionKey(NULL_S)
    );
  }

  @Test
  void producesNotNullWhenComputingSessionKey() {
    // When
    final var computedSessionKey = srp6ServerService.computeSessionKey(S);

    // Then
    assertThat(computedSessionKey, is(notNullValue()));
  }

  @Test
  void producesTheRightValueWhenComputingSessionKey() {
    // When
    final var computedSessionKey = srp6ServerService.computeSessionKey(S);

    // Then
    assertThat(computedSessionKey, is(equalTo(SESSION_KEY)));
  }

  @Test
  void producesTheSameValueWhenComputingTwoConsecutiveSessionKeyAndTheSameInputData() {
    // When
    final var computedSessionKey_1 = srp6ServerService.computeSessionKey(S);
    final var computedSessionKey_2 = srp6ServerService.computeSessionKey(S);

    // Then
    assertThat(computedSessionKey_1, is(equalTo(computedSessionKey_2)));
  }

  @Test
  void producesDifferentValuesWhenComputingTwoConsecutiveSessionKeyAndDifferentInputData() {
    // When
    final var computedSessionKey_1 = srp6ServerService.computeSessionKey(S);

    final var computedSessionKey_2 =
        srp6ServerService.computeSessionKey(
            toUnsignedByteArray(SRP6RFC5054TestingVectors.EXPECTED_S));

    // Then
    assertThat(computedSessionKey_1, is(not(equalTo(computedSessionKey_2))));
  }

  @Test
  void producesTheSameValueWhenComputingManyConsecutiveSessionKeyAndTheSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var computedSessionKeys =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6ServerService.computeSessionKey(S)));

    // Then
    assertThat(computedSessionKeys, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenComputingManyConsecutiveSessionKeyAndTheSameInputData() {
    // Given
    final var _100 = 100;

    // When
    final var computedSessionKeys =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> encodeHex(srp6ServerService.computeSessionKey(S)));

    // Then
    assertThat(computedSessionKeys.iterator().next(), is(equalTo(encodeHex(SESSION_KEY))));
  }

  @Test
  void producesTheSameValueWhenComputingConcurrentlyManySessionKeyAndTheSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var computedSessionKeys =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6ServerService.computeSessionKey(S)));

    // Then
    assertThat(computedSessionKeys, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenComputingConcurrentlyManySessionKeyAndTheSameInputData() {
    // Given
    final var _500 = 500;

    // When
    final var computedSessionKeys =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> encodeHex(srp6ServerService.computeSessionKey(S)));

    // Then
    assertThat(computedSessionKeys.iterator().next(), is(equalTo(encodeHex(SESSION_KEY))));
  }
}