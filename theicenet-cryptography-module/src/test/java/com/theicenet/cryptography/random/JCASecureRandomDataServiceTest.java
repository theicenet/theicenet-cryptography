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
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.number.IsCloseTo.closeTo;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.security.DrbgParameters;
import java.security.DrbgParameters.Capability;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Juan Fidalgo
 */
class JCASecureRandomDataServiceTest {

  final int RANDOM_DATA_LENGTH_1_BYTE = 1;
  final int RANDOM_DATA_LENGTH_16_BYTES = 16;
  final int RANDOM_DATA_LENGTH_32_BYTES = 32;

  SecureRandomDataService secureRandomDataService;


  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingRandomDataAndInvalidLength() {
    // Given
    secureRandomDataService = new JCASecureRandomDataService(SecureRandomAlgorithm.DEFAULT);

    final var RANDOM_DATA_LENGTH_MINUS_ONE = -1;

    // Then throws IllegalArgumentException
    assertThrows(
        IllegalArgumentException.class,
        () -> secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_MINUS_ONE)); // When generating random data and invalid length
  }

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesNotNullWhenGeneratingRandomData(SecureRandomAlgorithm algorithm) {
    // Given
    /*
    * If we fail here, we're likely on a Windows machines.
    * Skip these tests.
    */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }


    // When
    final var generatedData =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);

    // Then
    assertThat(generatedData, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesNotEmptyWhenGeneratingRandom(SecureRandomAlgorithm algorithm) {
    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

    // When
    final var generatedData =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);

    // Then
    assertThat(generatedData.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesDataWithTheRequestLengthWhenGeneratingRandomDataAnd16Bits(SecureRandomAlgorithm algorithm) {
    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

    // When
    final var generatedData =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);

    // Then
    assertThat(generatedData.length, is(equalTo(RANDOM_DATA_LENGTH_16_BYTES)));
  }

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesDataWithTheRequestLengthWhenGeneratingRandomDataAnd32Bits(SecureRandomAlgorithm algorithm) {
    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

    // When
    final var generatedData =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_32_BYTES);

    // Then
    assertThat(generatedData.length, is(equalTo(RANDOM_DATA_LENGTH_32_BYTES)));
  }

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesDifferentDataWhenGeneratingTwoConsecutiveRandomsDataWithTheSameLength(
      SecureRandomAlgorithm algorithm) {

    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

    // When generating two consecutive random data with the same length
    final var generatedData_1 =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);
    final var generatedData_2 =
        secureRandomDataService.generateSecureRandomData(RANDOM_DATA_LENGTH_16_BYTES);

    // Then the generated random data are different
    assertThat(generatedData_1, is(not(equalTo(generatedData_2))));
  }

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesDifferentDataWhenGeneratingManyConsecutiveRandomsDataWithTheSameLength(
      SecureRandomAlgorithm algorithm) {
    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

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

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesDifferentDataWhenGeneratingConcurrentlyManyRandomsDataWithTheSameLength(
      SecureRandomAlgorithm algorithm) {
    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

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

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesCryptographicallySecureRandomDataWhenGeneratingManyConsecutiveRandomsData(
      SecureRandomAlgorithm algorithm) {
    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

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

  @ParameterizedTest
  @EnumSource(SecureRandomAlgorithm.class)
  void producesCryptographicallySecureRandomDataWhenGeneratingConcurrentlyManyRandomsData(
      SecureRandomAlgorithm algorithm) {
    // Given
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService = new JCASecureRandomDataService(algorithm);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf("Skipping: %s no available%n", algorithm);
      return;
    }

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

  @Test
  void setsProperlyStrengthForDRBGAlgorithm() {
    // Given
    final int STRENGTH_256 = 256;
    final SecureRandomCapability CAPABILITY_PR_AND_RESEED = SecureRandomCapability.RESEED_ONLY;
    final int PERSONALIZATION_STRING_LENGTH = 16;

    // When
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService =
          new JCASecureRandomDataService(
              STRENGTH_256,
              CAPABILITY_PR_AND_RESEED,
              PERSONALIZATION_STRING_LENGTH);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf(
          "Skipping: DRBG with strength %s and capability %s no available%n",
          STRENGTH_256,
          CAPABILITY_PR_AND_RESEED);
      return;
    }

    // Then
    final var secureRandom = secureRandomDataService.getSecureRandom();
    final var params = (DrbgParameters.Instantiation) secureRandom.getParameters();
    final var strength = params.getStrength();

    assertThat(strength, is(equalTo(STRENGTH_256)));
  }

  @Test
  void setsProperlyCapabilityForDRBGAlgorithm() {
    // Given
    final int STRENGTH_256 = 256;
    final SecureRandomCapability CAPABILITY_PR_AND_RESEED = SecureRandomCapability.RESEED_ONLY;
    final int PERSONALIZATION_STRING_LENGTH = 16;

    // When
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService =
          new JCASecureRandomDataService(
              STRENGTH_256,
              CAPABILITY_PR_AND_RESEED,
              PERSONALIZATION_STRING_LENGTH);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf(
          "Skipping: DRBG with strength %s and capability %s no available%n",
          STRENGTH_256,
          CAPABILITY_PR_AND_RESEED);
      return;
    }

    // Then
    final var secureRandom = secureRandomDataService.getSecureRandom();
    final var params = (DrbgParameters.Instantiation) secureRandom.getParameters();
    final var capability = params.getCapability();

    assertThat(
        capability,
        is(equalTo(Capability.valueOf(CAPABILITY_PR_AND_RESEED.name()))));
  }

  @Test
  void setsProperlyPersonalizationStringForDRBGAlgorithm() {
    // Given
    final int STRENGTH_256 = 256;
    final SecureRandomCapability CAPABILITY_PR_AND_RESEED = SecureRandomCapability.RESEED_ONLY;
    final int PERSONALIZATION_STRING_LENGTH = 16;

    // When
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService =
          new JCASecureRandomDataService(
              STRENGTH_256,
              CAPABILITY_PR_AND_RESEED,
              PERSONALIZATION_STRING_LENGTH);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf(
          "Skipping: DRBG with strength %s and capability %s no available%n",
          STRENGTH_256,
          CAPABILITY_PR_AND_RESEED);
      return;
    }

    // Then
    final var secureRandom = secureRandomDataService.getSecureRandom();
    final var params = (DrbgParameters.Instantiation) secureRandom.getParameters();
    final var personalizationString = params.getPersonalizationString();

    assertThat(personalizationString.length, is(equalTo(PERSONALIZATION_STRING_LENGTH)));
  }

  @Test
  void setsNoPersonalizationStringForDRBGAlgorithmWhenNoRequested() {
    // Given
    final int STRENGTH_256 = 256;
    final SecureRandomCapability CAPABILITY_PR_AND_RESEED = SecureRandomCapability.RESEED_ONLY;

    // When
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService =
          new JCASecureRandomDataService(
              STRENGTH_256,
              CAPABILITY_PR_AND_RESEED);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf(
          "Skipping: DRBG with strength %s and capability %s no available%n",
          STRENGTH_256,
          CAPABILITY_PR_AND_RESEED);
      return;
    }

    // Then
    final var secureRandom = secureRandomDataService.getSecureRandom();
    final var params = (DrbgParameters.Instantiation) secureRandom.getParameters();
    final var personalizationString = params.getPersonalizationString();

    assertThat(personalizationString, is(nullValue()));
  }

  @Test
  void setsDifferentPersonalizationStringsForDRBGAlgorithm() {
    // Given
    final int STRENGTH_256 = 256;
    final SecureRandomCapability CAPABILITY_PR_AND_RESEED = SecureRandomCapability.RESEED_ONLY;
    final int PERSONALIZATION_STRING_LENGTH = 16;

    // When
    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */

    final SecureRandomDataService secureRandomDataService_1;
    final SecureRandomDataService secureRandomDataService_2;
    try {
      secureRandomDataService_1 =
          new JCASecureRandomDataService(
              STRENGTH_256,
              CAPABILITY_PR_AND_RESEED,
              PERSONALIZATION_STRING_LENGTH);

      secureRandomDataService_2 =
          new JCASecureRandomDataService(
              STRENGTH_256,
              CAPABILITY_PR_AND_RESEED,
              PERSONALIZATION_STRING_LENGTH);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf(
          "Skipping: DRBG with strength %s and capability %s no available%n",
          STRENGTH_256,
          CAPABILITY_PR_AND_RESEED);
      return;
    }

    // Then
    final var secureRandom_1 = secureRandomDataService_1.getSecureRandom();
    final var params_1 = (DrbgParameters.Instantiation) secureRandom_1.getParameters();
    final var personalizationString_1 = params_1.getPersonalizationString();

    final var secureRandom_2 = secureRandomDataService_2.getSecureRandom();
    final var params_2 = (DrbgParameters.Instantiation) secureRandom_2.getParameters();
    final var personalizationString_2 = params_2.getPersonalizationString();

    assertThat(personalizationString_1, is(not(equalTo(personalizationString_2))));
  }

  @ParameterizedTest
  @EnumSource(SecureRandomCapability.class)
  void producesCryptographicallySecureRandomDataWhenGeneratingManyConsecutiveRandomsDataAndDRBG(
      SecureRandomCapability capability) {
    // Given
    final int STRENGTH_256 = 256;
    final int PERSONALIZATION_STRING_LENGTH = 16;

    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService =
          new JCASecureRandomDataService(
              STRENGTH_256,
              capability,
              PERSONALIZATION_STRING_LENGTH);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf(
          "Skipping: DRBG with strength %s and capability %s no available%n",
          STRENGTH_256,
          capability);
      return;
    }

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

  @ParameterizedTest
  @EnumSource(SecureRandomCapability.class)
  void producesCryptographicallySecureRandomDataWhenGeneratingConcurrentlyManyRandomsDataAndDRBG(
      SecureRandomCapability capability) {
    // Given
    final int STRENGTH_256 = 256;
    final int PERSONALIZATION_STRING_LENGTH = 16;

    /*
     * If we fail here, we're likely on a Windows machines.
     * Skip these tests.
     */
    try {
      secureRandomDataService =
          new JCASecureRandomDataService(
              STRENGTH_256,
              capability,
              PERSONALIZATION_STRING_LENGTH);
    } catch (SecureRandomDataServiceException e) {
      System.out.printf(
          "Skipping: DRBG with strength %s and capability %s no available%n",
          STRENGTH_256,
          capability);
      return;
    }

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