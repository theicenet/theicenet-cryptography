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
package com.theicenet.cryptography.util;

import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_1024;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_1536;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_2048;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_3072;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_4096;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_6144;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_8192;
import static com.theicenet.cryptography.util.SRP6BigIntegerSafePrimeN.N_1024_BIG_INTEGER;
import static com.theicenet.cryptography.util.SRP6BigIntegerSafePrimeN.N_1536_BIG_INTEGER;
import static com.theicenet.cryptography.util.SRP6BigIntegerSafePrimeN.N_2048_BIG_INTEGER;
import static com.theicenet.cryptography.util.SRP6BigIntegerSafePrimeN.N_3072_BIG_INTEGER;
import static com.theicenet.cryptography.util.SRP6BigIntegerSafePrimeN.N_4096_BIG_INTEGER;
import static com.theicenet.cryptography.util.SRP6BigIntegerSafePrimeN.N_6144_BIG_INTEGER;
import static com.theicenet.cryptography.util.SRP6BigIntegerSafePrimeN.N_8192_BIG_INTEGER;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsArrayWithSize.arrayWithSize;
import static org.hamcrest.collection.IsArrayWithSize.emptyArray;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.test.support.HexUtil;
import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Juan Fidalgo
 */
class ByteArraysUtilTest {

  static final byte PAD_ZERO = (byte) 0;

  @Test
  void throwsIllegalArgumentExceptionWhenToUnsignedByteArrayAndNullValue() {
    // Given
    final BigInteger NULL_VALUE = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> ByteArraysUtil.toUnsignedByteArray(NULL_VALUE)); // When
  }

  @Test
  void producesNotNullWhenToUnsignedByteArray() {
    // Given
    final var ANY_VALUE = new BigInteger("1234567890");

    // When
    final var byteArrayRepresentation = ByteArraysUtil.toUnsignedByteArray(ANY_VALUE);

    // Then
    assertThat(byteArrayRepresentation, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenToUnsignedByteArray() {
    // Given
    final var ANY_VALUE = new BigInteger("1234567890");

    // When
    final var byteArrayRepresentation = ByteArraysUtil.toUnsignedByteArray(ANY_VALUE);

    // Then
    assertThat(byteArrayRepresentation.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("bigIntegerVsByteArrayMapRepresentation")
  void producesTheRightResultWhenToUnsignedByteArray(
      BigInteger value,
      byte[] expectedByteArrayRepresentation) {

    // When
    final var byteArrayRepresentation = ByteArraysUtil.toUnsignedByteArray(value);

    // Then
    assertThat(byteArrayRepresentation, is(equalTo(expectedByteArrayRepresentation)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenToBigIntegerAndNullArray() {
    // Given
    final byte[] NULL_BYTE_ARRAY = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> ByteArraysUtil.toBigInteger(NULL_BYTE_ARRAY)); // When

  }

  @Test
  void producesNotNullWhenToBigIntegerAndByteArray() {
    // When
    final var ANY_BYTE_ARRAY = new byte[]{4,0,1};

    // When
    final var value = ByteArraysUtil.toBigInteger(ANY_BYTE_ARRAY);

    // Then
    assertThat(value, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("bigIntegerVsByteArrayMapRepresentation")
  void producesTheRightResultWhenToBigIntegerAndByteArray(
      BigInteger expectedValue,
      byte[] byteArrayRepresentation) {

    // When
    final var value = ByteArraysUtil.toBigInteger(byteArrayRepresentation);

    // Then
    assertThat(value, is(equalTo(expectedValue)));
  }

  static Stream<Arguments> bigIntegerVsByteArrayMapRepresentation() {
    return Stream.of(
        Arguments.of(
            new BigInteger("0"),
            new byte[]{0}),
        Arguments.of(
            new BigInteger("1"),
            new byte[]{1}),
        Arguments.of(
            new BigInteger("10"),
            new byte[]{10}),
        Arguments.of(
            new BigInteger("1024"),
            new byte[]{4, 0}),
        Arguments.of(
            new BigInteger("2048"),
            new byte[]{8, 0}),
        Arguments.of(
            new BigInteger("5648"),
            new byte[]{22, 16}),
        Arguments.of(
            new BigInteger("1554442626553"),
            new byte[]{1, 105, -20, 0, 37, -7}),
        Arguments.of(N_1024_BIG_INTEGER, HexUtil.decodeHex(N_1024)),
        Arguments.of(N_1536_BIG_INTEGER, HexUtil.decodeHex(N_1536)),
        Arguments.of(N_2048_BIG_INTEGER, HexUtil.decodeHex(N_2048)),
        Arguments.of(N_3072_BIG_INTEGER, HexUtil.decodeHex(N_3072)),
        Arguments.of(N_4096_BIG_INTEGER, HexUtil.decodeHex(N_4096)),
        Arguments.of(N_6144_BIG_INTEGER, HexUtil.decodeHex(N_6144)),
        Arguments.of(N_8192_BIG_INTEGER, HexUtil.decodeHex(N_8192))
    );
  }

  @Test
  void throwsIllegalArgumentExceptionWhenToBigIntegerAndNullHex() {
    // Given
    final String NULL_HEX = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> ByteArraysUtil.toBigInteger(NULL_HEX)); // When
  }

  @Test
  void throwsIllegalArgumentExceptionWhenToBigIntegerAndInvalidHex() {
    // Given
    final String INVALID_HEX = "INVALID";

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> ByteArraysUtil.toBigInteger(INVALID_HEX)); // When
  }

  @Test
  void producesNotNullWhenToBigIntegerAndHex() {
    // When
    final var ANY_HEX = "4C6F3F16";

    // When
    final var value = ByteArraysUtil.toBigInteger(ANY_HEX);

    // Then
    assertThat(value, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("bigIntegerVsHexMapRepresentation")
  void producesTheRightResultWhenToBigIntegerAndHex(
      BigInteger expectedValue,
      String hexRepresentation) {

    // When
    final var value = ByteArraysUtil.toBigInteger(hexRepresentation);

    // Then
    assertThat(value, is(equalTo(expectedValue)));
  }

  static Stream<Arguments> bigIntegerVsHexMapRepresentation() {
    return Stream.of(
        Arguments.of(new BigInteger("0"), "00"),
        Arguments.of(new BigInteger("1"), "01"),
        Arguments.of(new BigInteger("10"), "0A"),
        Arguments.of(new BigInteger("1024"), "0400"),
        Arguments.of(new BigInteger("2048"), "0800"),
        Arguments.of(new BigInteger("5648"), "1610"),
        Arguments.of(new BigInteger("1554442626553"), "0169EC0025F9"),
        Arguments.of(N_1024_BIG_INTEGER, N_1024),
        Arguments.of(N_1536_BIG_INTEGER, N_1536),
        Arguments.of(N_2048_BIG_INTEGER, N_2048),
        Arguments.of(N_3072_BIG_INTEGER, N_3072),
        Arguments.of(N_4096_BIG_INTEGER, N_4096),
        Arguments.of(N_6144_BIG_INTEGER, N_6144),
        Arguments.of(N_8192_BIG_INTEGER, N_8192)
    );
  }

  @Test
  void producesEmptyWhenConcatenatingANullByteArray() {
    // Given
    final byte[] NULL_BYTE_ARRAY = null;

    // When
    final var concatenated = ByteArraysUtil.concat(NULL_BYTE_ARRAY);

    // Then
    assertThat(concatenated, is(equalTo(new byte[0])));
  }

  @Test
  void producesEmptyWhenConcatenatingOneSingleEmptyByteArray() {
    // Given
    final var EMPTY_BYTE_ARRAY = new byte[0];

    // When
    final var concatenated = ByteArraysUtil.concat(EMPTY_BYTE_ARRAY);

    // Then
    assertThat(concatenated, is(equalTo(new byte[0])));
  }

  @Test
  void producesEmptyWhenConcatenatingMultipleEmptyByteArrays() {
    // Given
    final var EMPTY_BYTE_ARRAY_1 = new byte[0];
    final var EMPTY_BYTE_ARRAY_2 = new byte[0];
    final var EMPTY_BYTE_ARRAY_3 = new byte[0];

    // When
    final var concatenated =
        ByteArraysUtil.concat(
            EMPTY_BYTE_ARRAY_1,
            EMPTY_BYTE_ARRAY_2,
            EMPTY_BYTE_ARRAY_3);

    // Then
    assertThat(concatenated, is(equalTo(new byte[0])));
  }

  @Test
  void producesTheSameWhenConcatenatingOneSingleNonEmptyByteArray() {
    // Given
    final var ANY_BYTE_ARRAY = new byte[]{37, 89, 117};

    // When
    final var concatenated = ByteArraysUtil.concat(ANY_BYTE_ARRAY);

    // Then
    assertThat(concatenated, is(equalTo(ANY_BYTE_ARRAY)));
  }

  @Test
  void producesTheRightResultWhenConcatenatingTwoNonEmptyByteArrays() {
    // Given
    final var ANY_BYTE_ARRAY_1 = new byte[]{37, 89, 117};
    final var ANY_BYTE_ARRAY_2 = new byte[]{11, 79};

    // When
    final var concatenated =
        ByteArraysUtil.concat(
            ANY_BYTE_ARRAY_1,
            ANY_BYTE_ARRAY_2);

    // Then
    assertThat(concatenated, is(equalTo(new byte[]{37, 89, 117, 11, 79})));
  }

  @Test
  void producesTheRightResultWhenConcatenatingMultipleNonEmptyByteArrays() {
    // Given
    final var ANY_BYTE_ARRAY_1 = new byte[]{37, 89, 117};
    final var ANY_BYTE_ARRAY_2 = new byte[]{11, 79};
    final var ANY_BYTE_ARRAY_3 = new byte[0];
    final var ANY_BYTE_ARRAY_4 = new byte[]{25, 43, 9, 8, 79};

    // When
    final var concatenated =
        ByteArraysUtil.concat(
            ANY_BYTE_ARRAY_1,
            ANY_BYTE_ARRAY_2,
            ANY_BYTE_ARRAY_3,
            ANY_BYTE_ARRAY_4);

    // Then
    assertThat(concatenated, is(equalTo(new byte[]{37, 89, 117, 11, 79, 25, 43, 9, 8, 79})));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenWhenPaddingLeftAndNullByteArray() {
    // Given
    final byte[] NULL_BYTE_ARRAY = null;
    final var ANY_LENGTH = 10;
    final var ANY_PADDING_VALUE = (byte) 1;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> ByteArraysUtil.padLeft(NULL_BYTE_ARRAY, ANY_LENGTH, ANY_PADDING_VALUE)); // When
  }

  @Test
  void producesNotNullWhenPaddingLeftAndEmptyByteArrayAndValueLength() {
    // Given
    final var ANY_BYTE_ARRAY_EMPTY = new byte[0];
    final var ANY_LENGTH = 10;

    // When
    final var paddedResult = ByteArraysUtil.padLeft(ANY_BYTE_ARRAY_EMPTY, ANY_LENGTH, PAD_ZERO);

    // Then
    assertThat(paddedResult, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenPaddingLeftAndEmptyByteArrayAndValueLength() {
    // Given
    final var ANY_BYTE_ARRAY_EMPTY = new byte[0];
    final var ANY_LENGTH = 10;

    // When
    final var paddedResult = ByteArraysUtil.padLeft(ANY_BYTE_ARRAY_EMPTY, ANY_LENGTH, PAD_ZERO);

    // Then
    assertThat(paddedResult.length, is(greaterThan(0)));
  }

  @Test
  void producesNotNullWhenPaddingLeftAndValidByteArrayAndLength() {
    // Given
    final var ANY_BYTE_ARRAY = new byte[]{4, 0};
    final var ANY_LENGTH = 10;

    // When
    final var paddedResult = ByteArraysUtil.padLeft(ANY_BYTE_ARRAY, ANY_LENGTH, PAD_ZERO);

    // Then
    assertThat(paddedResult, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenPaddingLeftAndValidByteArrayAndLength() {
    // Given
    final var ANY_BYTE_ARRAY = new byte[]{4, 0};
    final var ANY_LENGTH = 10;

    // When
    final var paddedResult = ByteArraysUtil.padLeft(ANY_BYTE_ARRAY, ANY_LENGTH, PAD_ZERO);

    // Then
    assertThat(paddedResult.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesNonPaddedResultWhenPaddingLeftAndValidByteArrayAndLengthIsNegative(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_1024 = new byte[]{4, 0};
    final var NEGATIVE_LENGTH = -1;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_1024,
            NEGATIVE_LENGTH,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(BINARY_BYTE_ARRAY_1024)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesNonPaddedResultWhenPaddingLeftAndEmptyByteArrayAndLengthIsNegative(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_EMPTY = new byte[0];
    final var NEGATIVE_LENGTH = -1;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_EMPTY,
            NEGATIVE_LENGTH,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(BINARY_BYTE_ARRAY_EMPTY)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesNonPaddedResultWhenPaddingLeftAndValidByteArrayAndLengthIsZero(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_1024 = new byte[]{4, 0};
    final var ZERO_LENGTH = 0;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_1024,
            ZERO_LENGTH,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(BINARY_BYTE_ARRAY_1024)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesNonPaddedResultWhenPaddingLeftAndEmptyByteArrayAndLengthIsZero(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_EMPTY = new byte[0];
    final var ZERO_LENGTH = 0;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_EMPTY,
            ZERO_LENGTH,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(BINARY_BYTE_ARRAY_EMPTY)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesNonPaddedResultWhenPaddingLeftAndValidByteArrayAndLengthIsOneLessThanByteArrayLength(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_1024 = new byte[]{4, 0};
    final var BYTE_ARRAY_LENGTH_MINUS_ONE = BINARY_BYTE_ARRAY_1024.length - 1;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_1024,
            BYTE_ARRAY_LENGTH_MINUS_ONE,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(BINARY_BYTE_ARRAY_1024)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesNonPaddedResultWhenPaddingLeftAndValidByteArrayAndLengthEqualsToByteArrayLength(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_1024 = new byte[]{4, 0};
    final var BYTE_ARRAY_LENGTH = BINARY_BYTE_ARRAY_1024.length;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_1024,
            BYTE_ARRAY_LENGTH,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(BINARY_BYTE_ARRAY_1024)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesNonPaddedResultWhenPaddingLeftAndEmptyByteArrayAndLengthEqualsZero(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_EMPTY = new byte[0];
    final var BYTE_ARRAY_LENGTH_ZERO = 0;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_EMPTY,
            BYTE_ARRAY_LENGTH_ZERO,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(BINARY_BYTE_ARRAY_EMPTY)));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesTheRightPaddedResultWhenPaddingLeftAndValidByteArrayAndLengthOneBiggerThanArrayLength(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_1024 = new byte[]{4, 0};
    final var BYTE_ARRAY_LENGTH = BINARY_BYTE_ARRAY_1024.length + 1;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_1024,
            BYTE_ARRAY_LENGTH,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(new byte[]{paddingValue, 4, 0})));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesTheRightPaddedResultWhenPaddingLeftAndEmptyByteArrayAndLengthIsOne(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_EMPTY = new byte[0];
    final var BYTE_ARRAY_LENGTH_ONE = 1;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_EMPTY,
            BYTE_ARRAY_LENGTH_ONE,
            paddingValue);

    // Then
    assertThat(paddedResult, is(equalTo(new byte[]{paddingValue})));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesTheRightPaddedResultWhenPaddingLeftAndValidByteArrayAndLengthTenBiggerThanArrayLength(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_1024 = new byte[]{4, 0};
    final var BYTE_ARRAY_LENGTH = BINARY_BYTE_ARRAY_1024.length + 10;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_1024,
            BYTE_ARRAY_LENGTH,
            paddingValue);

    // Then
    assertThat(paddedResult,
        is(equalTo(
            new byte[]{
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                4,
                0})));
  }

  @ParameterizedTest
  @ValueSource(bytes = {0, 1, 5, 10, 50, 127, -1, -3, -10, -128})
  void producesTheRightPaddedResultWhenPaddingLeftAndEmptyByteArrayAndLengthIsTen(byte paddingValue) {
    // Given
    final var BINARY_BYTE_ARRAY_EMPTY = new byte[0];
    final var BYTE_ARRAY_LENGTH_10 = 10;

    // When
    final var paddedResult =
        ByteArraysUtil.padLeft(
            BINARY_BYTE_ARRAY_EMPTY,
            BYTE_ARRAY_LENGTH_10,
            paddingValue);

    // Then
    assertThat(paddedResult,
        is(equalTo(
            new byte[]{
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue,
                paddingValue})));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenSplittingAndNullByteArrayAndNoIndexes() {
    // Given
    final byte[] NULL_BYTE_ARRAY = null;

    // When
    assertThrows(
        IllegalArgumentException.class,
        () -> ByteArraysUtil.split(NULL_BYTE_ARRAY)
    );
  }

  @Test
  void throwsIllegalArgumentExceptionWhenSplittingAndNullByteArrayAndIndexes() {
    // Given
    final byte[] NULL_BYTE_ARRAY = null;
    final var SPLIT_INDEX = 1;

    // When
    assertThrows(
        IllegalArgumentException.class,
        () -> ByteArraysUtil.split(NULL_BYTE_ARRAY, SPLIT_INDEX)
    );
  }

  @Test
  void producesNotNullWhenSplittingAndNoIndexes() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY);

    // Then
    assertThat(splitResult, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenSplittingAndNoIndexes() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY);

    // Then
    assertThat(splitResult, is(not(emptyArray())));
  }

  @Test
  void producesResultOfSizeOneWhenSplittingAndNoIndexes() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY);

    // Then
    assertThat(splitResult, is(arrayWithSize(1)));
  }

  @Test
  void producesTheSameArrayWhenSplittingAndNoIndexes() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY);

    // Then
    assertThat(splitResult, is(equalTo(new byte[][]{BYTE_ARRAY})));
  }

  @Test
  void producesNotNullWhenSplittingAndOneIndex() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX = 3;

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY, SPLIT_INDEX);

    // Then
    assertThat(splitResult, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenSplittingAndOneIndex() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX = 3;

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY, SPLIT_INDEX);

    // Then
    assertThat(splitResult, is(not(emptyArray())));
  }

  @Test
  void producesResultOfSizeTwoWhenSplittingAndOneIndex() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX = 3;

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY, SPLIT_INDEX);

    // Then
    assertThat(splitResult, is(arrayWithSize(2)));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndOneIndexWithinArray() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX_WITHIN_ARRAY = 3;

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY, SPLIT_INDEX_WITHIN_ARRAY);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndOneIndexEqualMinusOne() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX_MINUS_ONE = -1;

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY, SPLIT_INDEX_MINUS_ONE);

    // Then
    assertThat(splitResult, is(equalTo(new byte[][]{BYTE_ARRAY})));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndOneIndexEqualZero() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX_ZERO = 0;

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY, SPLIT_INDEX_ZERO);

    // Then
    assertThat(splitResult, is(equalTo(new byte[][]{BYTE_ARRAY})));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndOneIndexEqualOne() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX_ZERO = 1;

    // When
    final var splitResult = ByteArraysUtil.split(BYTE_ARRAY, SPLIT_INDEX_ZERO);

    // Then
    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0},
                    {1, 2, 3, 4}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndOneIndexEqualToByteArrayLength() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX_MINUS_BYTE_ARRAY_LENGTH = BYTE_ARRAY.length;

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEX_MINUS_BYTE_ARRAY_LENGTH);

    // Then
    assertThat(splitResult, is(equalTo(new byte[][]{BYTE_ARRAY})));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndOneIndexEqualToByteArrayLengthPlusOne() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX_MINUS_BYTE_ARRAY_LENGTH_PLUS_ONE = BYTE_ARRAY.length + 1;

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEX_MINUS_BYTE_ARRAY_LENGTH_PLUS_ONE);

    // Then
    assertThat(splitResult, is(equalTo(new byte[][]{BYTE_ARRAY})));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndOneIndexEqualToByteArrayLengthMinusOne() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4};
    final var SPLIT_INDEX_MINUS_BYTE_ARRAY_LENGTH_PLUS_ONE = BYTE_ARRAY.length - 1;

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEX_MINUS_BYTE_ARRAY_LENGTH_PLUS_ONE);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2, 3},
                    {4}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesAllInRangeWithNoDuplicatesAndSortedAsc() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{3, 6, 11, 14};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesAllInRangeWithDuplicatesAndSortedAsc() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{3, 3, 3, 6, 6, 6, 11, 14, 14, 14};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }


  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesAllInRangeWithNoDuplicatesAndSortedDesc() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{14, 11, 6, 3};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesAllInRangeWithNoDuplicatesAndUnsorted() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{6, 14, 3, 11};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesAllInRangeWithDuplicatesAndUnsorted() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{6, 11, 6, 14, 3, 11, 6, 11, 14, 11};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesSomeNotInRangeWithNoDuplicatesAndSortedAsc() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{-10, 3, 6, 11, 14, 20};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesSomeNotInRangeWithDuplicatesAndSortedAsc() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{-10, -10, 3, 3, 3, 6, 6, 6, 11, 14, 14, 14, 20, 20, 20};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesSomeNotInRangeWithNoDuplicatesAndSortedDesc() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{20, 14, 11, 6, 3, -10};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesSomeNotInRangeWithNoDuplicatesAndUnsorted() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC = new int[]{6, 14, -10, 3, 20, 11};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }

  @Test
  void producesTheRightSubArraysWhenSplittingAndMultipleIndexesSomeNotInRangeWithDuplicatesAndUnsorted() {
    // Given
    final var BYTE_ARRAY = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    final var SPLIT_INDEXES_NO_DUP_SORTED_ASC =
        new int[]{6, -10, 6, -10, 6, 14, 3, 20, 14, 20, 11, 3, 20, 11, 6};

    // When
    final var splitResult =
        ByteArraysUtil.split(
            BYTE_ARRAY,
            SPLIT_INDEXES_NO_DUP_SORTED_ASC);

    // Then
    assertThat(
        splitResult,
        is(equalTo(
            new byte[][]
                {
                    {0, 1, 2},
                    {3, 4, 5},
                    {6, 7, 8, 9, 10},
                    {11, 12, 13},
                    {14, 15}
                })));
  }
}