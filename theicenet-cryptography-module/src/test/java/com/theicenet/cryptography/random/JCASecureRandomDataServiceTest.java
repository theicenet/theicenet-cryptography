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
package com.theicenet.cryptography.random;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.IsCloseTo.closeTo;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Juan Fidalgo
 */
class JCASecureRandomDataServiceTest {

  final int RANDOM_DATA_LENGTH_1_BYTE = 1;
  final int RANDOM_DATA_LENGTH_16_BYTES = 16;
  final int RANDOM_DATA_LENGTH_32_BYTES = 32;

  SecureRandomDataService secureRandomDataService;

  @BeforeEach
  void setUp() {
    secureRandomDataService = new JCASecureRandomDataService(new SecureRandom());
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingRandomDataAndInvalidLength() {
    // Given
    final var RANDOM_DATA_LENGTH_MINUS_ONE = -1;

    // When generating random data and invalid length
    // Then throws IllegalArgumentException
    assertThrows(
        IllegalArgumentException.class,
        () -> secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_MINUS_ONE));
  }

  @Test
  void producesNotNullWhenGeneratingRandomData() {
    // When
    final var generatedData =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);

    // Then
    assertThat(generatedData, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenGeneratingRandom() {
    // When
    final var generatedData =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);

    // Then
    assertThat(generatedData.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      RANDOM_DATA_LENGTH_16_BYTES,
      RANDOM_DATA_LENGTH_32_BYTES})
  void producesDataWithTheRequestLengthWhenGeneratingRandomData(int randomDataLength) {
    // When
    final var generatedData = secureRandomDataService.generateSecureRandomData(randomDataLength);

    // Then
    assertThat(generatedData.length, is(equalTo(randomDataLength)));
  }

  @Test
  void producesDifferentDataWhenGeneratingTwoConsecutiveRandomsDataWithTheSameLength() {
    // When generating two consecutive random data with the same length
    final var generatedData_1 =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);
    final var generatedData_2 =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);

    // Then the generated random data are different
    assertThat(generatedData_1, is(not(equalTo(generatedData_2))));
  }

  @Test
  void producesDifferentDataWhenGeneratingManyConsecutiveRandomsDataWithTheSameLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive random data with the same length
    final var generatedDataSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES)));

    // Then all random data have been generated and all them are different
    assertThat(generatedDataSet, hasSize(_100));
  }

  @Test
  void producesDifferentDataWhenGeneratingConcurrentlyManyRandomsDataWithTheSameLength() {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random data with the same length
    final var generatedDataSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES)));

    // Then all data have been generated and all them are different
    assertThat(generatedDataSet, hasSize(_500));
  }

  @Test
  void producesCryptographicallySecureRandomDataWhenGeneratingManyConsecutiveRandomsData() {
    // Given
    final var _100_000 = 100_000;

    // When generating many random data with one byte length
    final var generatedDataList =
        RunnerUtil.runConsecutivelyToList(
            _100_000,
            () ->
                Byte.toUnsignedInt(
                    secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_1_BYTE)[0]));

    // Then calculating the sample frequencies for the statistical distribution
    final var frequencies = calculateSampleFrequencies(generatedDataList);

    // and Then its entropy
    final var entropy = calculateEntropy(_100_000, frequencies);

    // Then the entropy of the statistical distribution for all 8-bits random data produced
    // should be very close to 8 bits
    assertThat(entropy, is(closeTo(8.0 * RANDOM_DATA_LENGTH_1_BYTE, 0.01)));
  }

  @Test
  void producesCryptographicallySecureRandomDataWhenGeneratingConcurrentlyManyRandomsData() {
    // Given
    final var _500_CONCURRENT_THREADS = 500;
    final var _200_ITERATIONS = 200;

    // When generating many random data with one byte length
    final List<Integer> generatedDataList =
        IntStream.range(0, _200_ITERATIONS)
            .mapToObj(index ->
                RunnerUtil.runConsecutivelyToList(
                    _500_CONCURRENT_THREADS,
                    () ->
                        Byte.toUnsignedInt(
                            secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_1_BYTE)[0])))
            .flatMap(List::stream)
            .collect(Collectors.toUnmodifiableList());

    // Then calculating the sample frequencies for the statistical distribution
    final var frequencies = calculateSampleFrequencies(generatedDataList);

    // and Then its entropy
    final var entropy =
        calculateEntropy(
            _500_CONCURRENT_THREADS * _200_ITERATIONS,
            frequencies);

    // Then the entropy of the statistical distribution for all 8-bits random data produced
    // should be very close to 8 bits
    assertThat(entropy, is(closeTo(8.0 * RANDOM_DATA_LENGTH_1_BYTE, 0.01)));
  }

  List<Integer> calculateSampleFrequencies(List<Integer> generatedDataList) {
    return IntStream.range(0, 256)
        .mapToObj(index -> Collections.frequency(generatedDataList, index))
        .collect(Collectors.toUnmodifiableList());
  }

  double calculateEntropy(int totalNumberOfSamples, List<Integer> sampleFrequencies) {
    return sampleFrequencies.stream()
        .map(Double::valueOf)
        .map(frequency -> frequency / totalNumberOfSamples)
        .map(probability -> -1.0d * probability * (Math.log(probability) / Math.log(2)))
        .mapToDouble(t -> t).sum();
  }
}