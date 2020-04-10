/*
 * Copyright 2019-2020 the original author or authors.
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
package com.theicenet.cryptography.randomise.iv;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.randomise.RandomiseService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Juan Fidalgo
 */
class JCAIVServiceTest {

  final int IV_LENGTH_16_BYTES = 16;
  final int IV_LENGTH_32_BYTES = 32;

  RandomiseService ivService;

  @BeforeEach
  void setUp() {
    ivService = new JCAIVService(new SecureRandom());
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingRandomAndInvalidIVLength() {
    // Given
    final var IV_LENGTH_MINUS_ONE = -1;

    // When generating IV and invalid IV length
    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> ivService.generateRandom(IV_LENGTH_MINUS_ONE));
  }

  @Test
  void producesNotNullWhenGeneratingRandom() {
    // When
    final var generatedIV = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then
    assertThat(generatedIV, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenGeneratingRandom() {
    // When
    final var generatedIV = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then
    assertThat(generatedIV.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      IV_LENGTH_16_BYTES,
      IV_LENGTH_32_BYTES})
  void producesIVWithTheRequestLengthWhenGeneratingRandom(int ivLength) {
    // When
    final var generatedIV = ivService.generateRandom(ivLength);

    // Then
    assertThat(generatedIV.length, is(equalTo(ivLength)));
  }

  @Test
  void producesDifferentIVsWhenGeneratingTwoConsecutiveRandomsWithTheSameLength() {
    // When generating two consecutive random IVs with the same length
    final var generatedIV_1 = ivService.generateRandom(IV_LENGTH_16_BYTES);
    final var generatedIV_2 = ivService.generateRandom(IV_LENGTH_16_BYTES);

    // Then the generated random IVs are different
    assertThat(generatedIV_1, is(not(equalTo(generatedIV_2))));
  }

  @Test
  void producesDifferentIVsWhenGeneratingManyConsecutiveRandomsWithTheSameLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive random IVs with the same length
    final var generatedIVsSet =
        RunnerUtil.runConsecutively(
            _100,
            () -> HexUtil.encodeHex(ivService.generateRandom(IV_LENGTH_16_BYTES)));

    // Then all IVs have been generated and all them are different
    assertThat(generatedIVsSet, hasSize(_100));
  }

  @Test
  void producesDifferentIVsWhenGeneratingConcurrentlyManyRandomsWithTheSameLength() throws Exception {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random IVs with the same length
    final var generatedIVsSet =
        RunnerUtil.runConcurrently(
            _500,
            () ->
                HexUtil.encodeHex(ivService.generateRandom(IV_LENGTH_16_BYTES)));

    // Then all IVs have been generated and all them are different
    assertThat(generatedIVsSet, hasSize(_500));
  }
}