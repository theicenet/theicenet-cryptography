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

import static com.theicenet.cryptography.test.support.HexUtil.decodeHex;
import static com.theicenet.cryptography.util.SecureEqualUtil.areEqual;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.number.OrderingComparison.lessThan;

import com.theicenet.cryptography.test.support.RunnerUtil;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class SecureEqualUtilTest {

  final byte[] VALUE =
      decodeHex(
          "7F35FA7767ECCF39AD7CEB1E23179933421D5858D9484D0C052AF5BB601BA3125E855D286C0078B66A4BCED4"
              + "A76BF2477B588C61C5A5A074D54FADC64C12C45F94DF263BEB57E4C659817EE1D311E197B219207782"
              + "7DFE83C6163BB04AC26B4098ADF59C4DFDADB1E811E152CE053F0A5AFD75097D0B130AE8EBCDB5EB2F"
              + "8D632D017B2F0B487EC11B1097AB447E082DA8950588A53946611249D67B8FD67AF1A6CA9F8E3EC843"
              + "B248CC033A863F7DAD06A6883B32DA3A98FB3E6C56AFA7B6DF5FC2C1D1B62AAC25C553C62CE90A3417"
              + "D2D4F6EA59B1F60382A56464BB3514CB62FA207BF7309698CCBC43945236077AC1407A9C913A66698B"
              + "85C6A830958FBD");

  final byte[] EQUAL_VALUE = VALUE.clone();

  final byte[] DIFFERENT_VALUE_EQUAL_LENGTH =
      decodeHex(
          "2655975C9039C313C1EDBDE4A17B8BCD72E844C9EA989ABE2C9030ADC53889139D4B89803BA82F4382001F1E"
              + "3D54BB51DEFF546AF1CB7289DBB7AC164902AB3DD6F67C8AE46ABCBAF88BAA934613D3AA9A04F210D1"
              + "AA5FB28D55A4DEEFD0C61431F4AA1AB15EB2CBBE1FE6A9A4B72623DD64EDA087736B118FD1F15883A7"
              + "5A1D89B178C490AFCF2482E2B1C84982BB56A5B6C0288FBF639F26F8AFA337F9B322C02C0551BFE5AE"
              + "202BC1EADA3B9E27712FB9261C178DD497261A073757B1D0D8EF71C11C05F2C3614589C3D85F31BE9A"
              + "E2FE17CC599FE71515E3C2104AB7F3D47BF1E75566A2CBDC3F829857F3F1661FEA1FCDE8FED5643AFB"
              + "E916CEC9035DB7");

  final byte[] DIFFERENT_VALUE_DIFFERENT_LENGTH = new byte[]{1};

  final int ITERATIONS = 100_000_000;

  @Test
  void producesTheRightResultWhenAreEqualAndBothNull() {
    // Given
    final byte[] NULL_A = null;
    final byte[] NULL_B = null;

    // When
    final var equalityResult = areEqual(NULL_A, NULL_B);

    // Then
    assertThat(equalityResult, is(equalTo(true)));
  }

  @Test
  void producesTheRightResultWhenAreEqualAndOnlyNullA() {
    // Given
    final byte[] NULL_A = null;

    // When
    final var equalityResult = areEqual(NULL_A, VALUE);

    // Then
    assertThat(equalityResult, is(equalTo(false)));
  }

  @Test
  void producesTheRightResultWhenAreEqualAndOnlyNullB() {
    // Given
    final byte[] NULL_B = null;

    // When
    final var equalityResult = areEqual(VALUE, NULL_B);

    // Then
    assertThat(equalityResult, is(equalTo(false)));
  }

  @Test
  void producesTheRightResultWhenAreEqualAndDifferentLength() {
    // When
    final var equalityResult = areEqual(VALUE, DIFFERENT_VALUE_DIFFERENT_LENGTH);

    // Then
    assertThat(equalityResult, is(equalTo(false)));
  }

  @Test
  void producesTheRightResultWhenAreEqualAndBothAreEqual() {
    // When
    final var equalityResult = areEqual(VALUE, EQUAL_VALUE);

    // Then
    assertThat(equalityResult, is(equalTo(true)));
  }

  @Test
  void producesTheRightResultWhenAreEqualAndBothAreDifferent() {
    // When
    final var equalityResult = areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH);

    // Then
    assertThat(equalityResult, is(equalTo(false)));
  }

  @Test
  void takesSimilarTimeWhenAreEqualsInBothPossibleResultsAndSameArrayLength() {
    // When same value
    final long initWhenEqual = System.currentTimeMillis();
    for (int count = 0; count < ITERATIONS; count++) {
      areEqual(VALUE, EQUAL_VALUE);
    }
    final long endWhenEqual = System.currentTimeMillis();

    final long timeWhenEqual = endWhenEqual - initWhenEqual;

    // And when different value same length
    final long initWhenDifferent = System.currentTimeMillis();
    for (int count = 0; count < ITERATIONS; count++) {
      areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH);
    }
    final long endWhenDifferent = System.currentTimeMillis();

    final long timeWhenDifferent = endWhenDifferent - initWhenDifferent;

    // Then times in equal and different path will be similar
    assertThat(Math.abs(timeWhenEqual - timeWhenDifferent), is(lessThan(2000L)));
  }

  @Test
  void producesTheSameValueWhenAreEqualsAndEqualByteArrays() {
    // When
    final var equalityResult_1 = areEqual(VALUE, EQUAL_VALUE);
    final var equalityResult_2 = areEqual(VALUE, EQUAL_VALUE);

    // Then
    assertThat(equalityResult_1, is(equalTo(equalityResult_2)));
  }

  @Test
  void producesTheSameValueWhenAreEqualsAndDifferentByteArrays() {
    // When
    final var equalityResult_1 = areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH);

    final var equalityResult_2 = areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH);

    // Then
    assertThat(equalityResult_1, is(equalTo(equalityResult_2)));
  }

  @Test
  void producesTheSameValueWhenAreEqualAndManyConsecutiveEqualByteArrays() {
    // Given
    final var _100 = 100;

    // When
    final var equalityResults =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> areEqual(VALUE, EQUAL_VALUE));

    // Then
    assertThat(equalityResults, hasSize(1));
  }

  @Test
  void producesTheSameValueWhenAreEqualAndManyConsecutiveDifferentByteArrays() {
    // Given
    final var _100 = 100;

    // When
    final var equalityResults =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH));

    // Then
    assertThat(equalityResults, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenAreEqualAndManyConsecutiveEqualByteArrays() {
    // Given
    final var _100 = 100;

    // When
    final var equalityResults =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> areEqual(VALUE, EQUAL_VALUE));

    // Then
    assertThat(equalityResults.iterator().next(), is(true));
  }

  @Test
  void producesTheRightValueWhenAreEqualAndManyConsecutiveDifferentByteArrays() {
    // Given
    final var _100 = 100;

    // When
    final var equalityResults =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH));

    // Then
    assertThat(equalityResults.iterator().next(), is(false));
  }

  @Test
  void producesTheSameValueWhenAreEqualsAndManyConcurrentEqualByteArrays() {
    // Given
    final var _500 = 500;

    // When
    final var equalityResults =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> areEqual(VALUE, EQUAL_VALUE));

    // Then
    assertThat(equalityResults, hasSize(1));
  }

  @Test
  void producesTheSameValueWhenAreEqualsAndManyConcurrentDifferentByteArrays() {
    // Given
    final var _500 = 500;

    // When
    final var equalityResults =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH));

    // Then
    assertThat(equalityResults, hasSize(1));
  }

  @Test
  void producesTheRightValueWhenAreEqualsAndManyConcurrentEqualByteArrays() {
    // Given
    final var _500 = 500;

    // When
    final var equalityResults =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> areEqual(VALUE, EQUAL_VALUE));

    // Then
    assertThat(equalityResults.iterator().next(), is(true));
  }

  @Test
  void producesTheRightValueWhenAreEqualsAndManyConcurrentDifferentByteArrays() {
    // Given
    final var _500 = 500;

    // When
    final var equalityResults =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> areEqual(VALUE, DIFFERENT_VALUE_EQUAL_LENGTH));

    // Then
    assertThat(equalityResults.iterator().next(), is(false));
  }
}