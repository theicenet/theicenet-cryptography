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
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_A;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_B;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_K;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_M1;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_M2;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_S;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_SESSION_KEY;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.EXPECTED_U;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.HASH_SHA_256;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.N;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GenericTestingVectors.g;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_1024;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_1536;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_2048;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_3072;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_4096;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_6144;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_8192;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.collection.IsEmptyCollection.empty;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author Juan Fidalgo
 */
class SRP6CommonUtilTest {

  final SecureRandom secureRandom = new SecureRandom();

  final DigestService sha256Digest = new JCADigestService(HASH_SHA_256);

  @Test
  void throwsIllegalArgumentExceptionWhenComputingKAndNullDigest() {
    // Given
    final DigestService NULL_DIGEST_SERVICE = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeK(NULL_DIGEST_SERVICE, N, g)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingKAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeK(sha256Digest, NULL_N, g)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingKAndNullG() {
    // Given
    final BigInteger NULL_G = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeK(sha256Digest, N, NULL_G)); // When
  }

  @Test
  void producesNotNullWhenComputingK() {
    // When
    final var computedK = SRP6CommonUtil.computeK(sha256Digest, N, g);

    // Then
    assertThat(computedK, is(notNullValue()));
  }

  @Test
  void producesTheRightKWhenComputingK() {
    // When
    final var computedK = SRP6CommonUtil.computeK(sha256Digest, N, g);

    // Then
    assertThat(computedK, is(equalTo(EXPECTED_K)));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingUAndNullDigest() {
    // Given
    final DigestService NULL_DIGEST_SERVICE = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeU(NULL_DIGEST_SERVICE, N, EXPECTED_A, EXPECTED_B)); // When
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingUAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeU(sha256Digest, NULL_N, EXPECTED_A, EXPECTED_B)); // When
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingUAndNullPublicValueA() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeU(sha256Digest, N, NULL_PUBLIC_VALUE_A, EXPECTED_B)); // When
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingUAndNullPublicValueB() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_B = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeU(sha256Digest, N, EXPECTED_A, NULL_PUBLIC_VALUE_B)); // When
  }

  @Test
  void producesNotNullWhenComputingU() {
    // When
    final var computedU = SRP6CommonUtil.computeU(sha256Digest, N, EXPECTED_A, EXPECTED_B);

    // Then
    assertThat(computedU, is(notNullValue()));
  }

  @Test
  void producesTheRightUWhenComputingU() {
    // When
    final var computedU = SRP6CommonUtil.computeU(sha256Digest, N, EXPECTED_A, EXPECTED_B);

    // Then
    assertThat(computedU, is(equalTo(EXPECTED_U)));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM1AndNullDigest() {
    // Given
    final DigestService NULL_DIGEST_SERVICE = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM1(
                NULL_DIGEST_SERVICE,
                N,
                EXPECTED_A,
                EXPECTED_B,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM1AndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM1(
                sha256Digest,
                NULL_N,
                EXPECTED_A,
                EXPECTED_B,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM1AndNullPublicValueA() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SRP6CommonUtil.computeM1(
                sha256Digest,
                N,
                NULL_PUBLIC_VALUE_A,
                EXPECTED_B,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM1AndNullPublicValueB() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_B = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM1(
                sha256Digest,
                N,
                EXPECTED_A,
                NULL_PUBLIC_VALUE_B,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM1AndNullS() {
    // Given
    final BigInteger NULL_S = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM1(
                sha256Digest,
                N,
                EXPECTED_A,
                EXPECTED_B,
                NULL_S));
  }

  @Test
  void producesNotNullWhenComputingM1() {
    // When
    final var computedM1 =
        SRP6CommonUtil.computeM1(
            sha256Digest,
            N, EXPECTED_A,
            EXPECTED_B,
            EXPECTED_S);

    // Then
    assertThat(computedM1, is(notNullValue()));
  }

  @Test
  void producesTheRightM1WhenComputingM1() {
    // When
    final var computedM1 =
        SRP6CommonUtil.computeM1(
            sha256Digest,
            N, EXPECTED_A,
            EXPECTED_B,
            EXPECTED_S);

    // Then
    assertThat(computedM1, is(equalTo(EXPECTED_M1)));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM2AndNullDigest() {
    // Given
    final DigestService NULL_DIGEST_SERVICE = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM2(
                NULL_DIGEST_SERVICE,
                N,
                EXPECTED_A,
                EXPECTED_M1,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM2AndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM2(
                sha256Digest,
                NULL_N,
                EXPECTED_A,
                EXPECTED_M1,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM2AndNullPublicValueA() {
    // Given
    final BigInteger NULL_PUBLIC_VALUE_A = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM2(
                sha256Digest,
                N,
                NULL_PUBLIC_VALUE_A,
                EXPECTED_M1,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM2AndNullM1() {
    // Given
    final BigInteger NULL_M1 = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM2(
                sha256Digest,
                N,
                EXPECTED_A,
                NULL_M1,
                EXPECTED_S));
  }

  @Test
  void throwIllegalArgumentExceptionWhenComputingM2AndNullS() {
    // Given
    final BigInteger NULL_S = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> // When
            SRP6CommonUtil.computeM2(
                sha256Digest,
                N,
                EXPECTED_A,
                EXPECTED_M1,
                NULL_S));
  }

  @Test
  void producesNotNullWhenComputingM2() {
    // When
    final var computedM2 =
        SRP6CommonUtil.computeM2(
            sha256Digest,
            N,
            EXPECTED_A,
            EXPECTED_M1,
            EXPECTED_S);

    // Then
    assertThat(computedM2, is(notNullValue()));
  }

  @Test
  void producesTheRightResultWhenComputingM2() {
    // When
    final var computedM2 =
        SRP6CommonUtil.computeM2(
            sha256Digest,
            N,
            EXPECTED_A,
            EXPECTED_M1,
            EXPECTED_S);

    // Then
    assertThat(computedM2, is(equalTo(EXPECTED_M2)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSessionKeyAndNullDigest() {
    // Given
    final DigestService NULL_DIGEST_SERVICE = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeSessionKey(NULL_DIGEST_SERVICE, N, EXPECTED_S)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSessionKeyAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeSessionKey(sha256Digest, NULL_N, EXPECTED_S)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenComputingSessionKeyAndNullS() {
    // Given
    final BigInteger NULL_S = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.computeSessionKey(sha256Digest, N, NULL_S)); // When
  }

  @Test
  void producesNotNullWhenComputingSessionKey() {
    // When
    final var computedSessionKey = SRP6CommonUtil.computeSessionKey(sha256Digest, N, EXPECTED_S);

    // Then
    assertThat(computedSessionKey, is(notNullValue()));
  }
  
  @Test
  void producesTheRightResultWhenComputingSessionKey() {
    // When
    final var computedSessionKey = SRP6CommonUtil.computeSessionKey(sha256Digest, N, EXPECTED_S);

    // Then
    assertThat(computedSessionKey, is(equalTo(EXPECTED_SESSION_KEY)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingPrivateValueAndNullN() {
    // Given
    final BigInteger NULL_N = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.generatePrivateValue(NULL_N, secureRandom)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingPrivateValueAndNullSecureRandom() {
    // Given
    final SecureRandom NULL_SECURE_RANDOM = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> SRP6CommonUtil.generatePrivateValue(N, NULL_SECURE_RANDOM)); // When
  }

  @Test
  void producesNotNullWhenGeneratingPrivateValue() {
    // When
    final var generatedPrivateValue = SRP6CommonUtil.generatePrivateValue(N, secureRandom);

    // Then
    assertThat(generatedPrivateValue, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("safePrimeForDifferentLengths")
  void producesValueWithLengthAtLeast256BitsWhenGeneratingPrivateValue(BigInteger safePrimeN) {
    // When
    final var generatedPrivateValue = SRP6CommonUtil.generatePrivateValue(safePrimeN, secureRandom);

    //Then
    assertThat(generatedPrivateValue.bitLength(), is(greaterThanOrEqualTo(256)));
  }

  @ParameterizedTest
  @MethodSource("safePrimeForDifferentLengths")
  void producesValueWithLengthAtLeast256BitsWhenGeneratingManyConsecutivePrivateValues(BigInteger safePrimeN) {
    // Given
    final var _10_000 = 10_000;

    // When
    final var generatedPrivateValuesList =
        RunnerUtil.runConsecutivelyToList(
            _10_000,
            () -> SRP6CommonUtil.generatePrivateValue(safePrimeN, secureRandom));

    //Then
    assertThat(
        generatedPrivateValuesList.stream()
            .map(BigInteger::bitLength)
            .filter(l -> l < 256)
            .collect(Collectors.toUnmodifiableList()),
        is(empty()));
  }

  @ParameterizedTest
  @MethodSource("safePrimeForDifferentLengths")
  void producesDifferentValuesWhenGeneratingManyConsecutivePrivateValues(BigInteger safePrimeN) {
    // Given
    final var _10_000 = 10_000;

    // When
    final var generatedPrivateValuesSet =
        RunnerUtil.runConsecutivelyToSet(
            _10_000,
            () -> SRP6CommonUtil.generatePrivateValue(safePrimeN, secureRandom));

    //Then
    assertThat(generatedPrivateValuesSet, hasSize(_10_000));
  }

  @ParameterizedTest
  @MethodSource("safePrimeForDifferentLengths")
  void producesValueWithLengthAtLeast256BitsWhenGeneratingConcurrentlyManyPrivateValues(BigInteger safePrimeN) {
    // Given
    final var _500 = 500;

    // When
    final var generatedPrivateValuesList =
        RunnerUtil.runConcurrentlyToList(
            _500,
            () -> SRP6CommonUtil.generatePrivateValue(safePrimeN, secureRandom));

    //Then
    assertThat(
        generatedPrivateValuesList.stream()
            .map(BigInteger::bitLength)
            .filter(l -> l < 256)
            .collect(Collectors.toUnmodifiableList()),
        is(empty()));
  }

  @ParameterizedTest
  @MethodSource("safePrimeForDifferentLengths")
  void producesDifferentValuesWhenGeneratingConcurrentlyManyPrivateValues(BigInteger safePrimeN) {
    // Given
    final var _500 = 500;

    // When
    final var generatedPrivateValuesSet =
        RunnerUtil.runConcurrentlyToList(
            _500,
            () -> SRP6CommonUtil.generatePrivateValue(safePrimeN, secureRandom));

    //Then
    assertThat(generatedPrivateValuesSet, hasSize(_500));
  }

  static Stream<Arguments> safePrimeForDifferentLengths() {
    return Stream.of(
        Arguments.of(new BigInteger("0")), // 0 bits
        Arguments.of(new BigInteger("1")), // 1 bit
        Arguments.of(new BigInteger("128")), // 8 bits
        Arguments.of(new BigInteger("365079631")), // 64 bits
        Arguments.of(new BigInteger("95109301086108025024082983357647711967")), // 256 bits
        Arguments.of(toBigInteger(N_1024)),
        Arguments.of(toBigInteger(N_1536)),
        Arguments.of(toBigInteger(N_2048)),
        Arguments.of(toBigInteger(N_3072)),
        Arguments.of(toBigInteger(N_4096)),
        Arguments.of(toBigInteger(N_6144)),
        Arguments.of(toBigInteger(N_8192))
    );
  }

  @Test
  void producesTheRightResultWhenValidatingPublicValueAndValidPublicValue() {
    // Given
    final var VALID_PUBLIC_VALUE = N.multiply(BigInteger.TEN).add(BigInteger.ONE);

    // When
    final var validationResult = SRP6CommonUtil.isValidPublicValue(N, VALID_PUBLIC_VALUE);

    // Then
    assertThat(validationResult, is(true));
  }

  @Test
  void producesTheRightResultWhenValidatingPublicValueAndInvalidPublicValue() {
    // Given
    final var INVALID_PUBLIC_VALUE = N.multiply(BigInteger.TEN);

    // When
    final var validationResult = SRP6CommonUtil.isValidPublicValue(N, INVALID_PUBLIC_VALUE);

    // Then
    assertThat(validationResult, is(false));
  }

  @Test
  void producesNotNullWhenCalculatingPadLength() {
    // Given
    final var ANY_VALUE = new BigInteger("1234567890");;

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(ANY_VALUE);

    // Then
    assertThat(calculatedPadLength, is(notNullValue()));
  }

  @Test
  void producesTheRightPadLengthWhenCalculatingPadLengthAndNLengthIs_0_Bits() {
    // Given
    final var _0_BITS_N = new BigInteger("0");;

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(_0_BITS_N);

    // Then
    assertThat(calculatedPadLength, is(equalTo(0)));
  }

  @Test
  void producesTheRightPadLengthWhenCalculatingPadLengthAndNLengthIs_1_Bits() {
    // Given
    final var _1_BITS_N = new BigInteger("1");

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(_1_BITS_N);

    // Then
    assertThat(calculatedPadLength, is(equalTo(1)));
  }

  @Test
  void producesTheRightPadLengthWhenCalculatingPadLengthAndNLengthIs_2_Bits() {
    // Given
    final var _2_BITS_N = new BigInteger("2");

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(_2_BITS_N);

    // Then
    assertThat(calculatedPadLength, is(equalTo(1)));
  }

  @Test
  void producesTheRightPadLengthWhenCalculatingPadLengthAndNLengthIs_7_Bits() {
    // Given
    final var _7_BITS_N = new BigInteger("65");

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(_7_BITS_N);

    // Then
    assertThat(calculatedPadLength, is(equalTo(1)));
  }

  @Test
  void producesTheRightPadLengthWhenCalculatingPadLengthAndNLengthIs_8_Bits() {
    // Given
    final var _8_BITS_N = new BigInteger("129");

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(_8_BITS_N);

    // Then
    assertThat(calculatedPadLength, is(equalTo(1)));
  }

  @Test
  void producesTheRightPadLengthWhenCalculatingPadLengthAndNLengthIs_9_Bits() {
    // Given
    final var _9_BITS_N = new BigInteger("257");

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(_9_BITS_N);

    // Then
    assertThat(calculatedPadLength, is(equalTo(2)));
  }

  @Test
  void producesTheRightPadLengthWhenCalculatingPadLengthAndNLengthIs_47_Bits() {
    // Given
    final var _47_BITS_N = new BigInteger("123456789012345");

    // When
    final var calculatedPadLength = SRP6CommonUtil.calculatePadLength(_47_BITS_N);

    // Then
    assertThat(calculatedPadLength, is(equalTo(6)));
  }
}