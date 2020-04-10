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
package com.theicenet.cryptography.mac.hmac;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.mac.MacService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author Juan Fidalgo
 */
class JCAHmacServiceTest {

  final String AES = "AES";

  final byte[] CONTENT =
      "Content to HMAC with different algorithm to check the MAC calc implementation is correct"
          .getBytes(StandardCharsets.UTF_8);

  final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  @ParameterizedTest
  @EnumSource(HmacAlgorithm.class)
  void producesNotNullWhenCalculatingMacForByteArray(HmacAlgorithm algorithm) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            CONTENT);

    // Then
    assertThat(mac, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(HmacAlgorithm.class)
  void producesNotNullWhenCalculatingMacForStream(HmacAlgorithm algorithm) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(mac, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithHMacAlgorithmAndItsHMacSizeInBits")
  void producesTheRightMacSizeWhenCalculatingMacForByteArray(HmacAlgorithm algorithm, Integer macSizeInBits) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            CONTENT);

    // Then
    assertThat(mac.length * 8, is(equalTo(macSizeInBits)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithHMacAlgorithmAndItsHMacSizeInBits")
  void producesTheRightMacSizeWhenCalculatingMacForStream(HmacAlgorithm algorithm, Integer macSizeInBits) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(mac.length * 8, is(equalTo(macSizeInBits)));
  }

  static Stream<Arguments> argumentsWithHMacAlgorithmAndItsHMacSizeInBits() {
    return Stream.of(
        Arguments.of(HmacAlgorithm.HmacSHA1, 160),
        Arguments.of(HmacAlgorithm.HmacSHA224, 224),
        Arguments.of(HmacAlgorithm.HmacSHA256, 256),
        Arguments.of(HmacAlgorithm.HmacSHA384, 384),
        Arguments.of(HmacAlgorithm.HmacSHA512, 512)
    );
  }

  @ParameterizedTest
  @EnumSource(HmacAlgorithm.class)
  void producesMacDifferentToContentWhenCalculatingMacForByteArray(HmacAlgorithm algorithm) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            CONTENT);

    // Then
    assertThat(mac, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @EnumSource(HmacAlgorithm.class)
  void producesMacDifferentToContentWhenCalculatingMacForStream(HmacAlgorithm algorithm) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(mac, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithHMacAlgorithmAndExpectedCalculatrdMac")
  void producesTheRightMacWhenCalculatingMacForByteArray(HmacAlgorithm algorithm, byte[] expectedMac) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            CONTENT);

    // Then
    assertThat(mac, is(equalTo(expectedMac)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithHMacAlgorithmAndExpectedCalculatrdMac")
  void producesTheRightMacWhenCalculatingMacForStream(HmacAlgorithm algorithm, byte[] expectedMac) {
    // Given
    final MacService macService = new JCAHmacService(algorithm);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(mac, is(equalTo(expectedMac)));
  }

  static Stream<Arguments> argumentsWithHMacAlgorithmAndExpectedCalculatrdMac() {
    return Stream.of(
        Arguments.of(
            HmacAlgorithm.HmacSHA1,
            HexUtil.decodeHex("7a9906e47cee2ab43200fd49dbc3b7c06cd9ff47")),
        Arguments.of(
            HmacAlgorithm.HmacSHA224,
            HexUtil.decodeHex("969785752931a5cfbc3709cfc0ab5f8d19a61e8b61cf8a35dd62e77c")),
        Arguments.of(
            HmacAlgorithm.HmacSHA256,
            HexUtil.decodeHex("022edc482e40113aa63efcb75f90752fc93a97ddfcc52f16e503d26c8559fa48")),
        Arguments.of(
            HmacAlgorithm.HmacSHA384,
            HexUtil.decodeHex(
                "b29240613dfbf087666fc4ef35df082df93fb84f0ff92931271a36f80e5c"
                    + "f192883e5201e45e1b3de40814c60e3eda77")),
        Arguments.of(
            HmacAlgorithm.HmacSHA512,
            HexUtil.decodeHex(
                "aecd4dc2c7c34952a93dd93b1d2c0b50b420690c5eb176dd6defe17667a50f"
                    + "e806624a798d3cc03fde40ba4308354582d8b996be7680693bac91331a37a"
                    + "2cf74"))
    );
  }

  @Test
  void producesTheSameMacWhenCalculatingTwoConsecutiveMacsForSameContentAndPrivateKeyForByteArray() {
    // Given
    final MacService macService = new JCAHmacService(HmacAlgorithm.HmacSHA1);

    // When
    final var mac_1 = macService.calculateMac(SECRET_KEY_1234567890123456_128_BITS, CONTENT);
    final var mac_2 = macService.calculateMac(SECRET_KEY_1234567890123456_128_BITS, CONTENT);

    // Then
    assertThat(mac_1, is(equalTo(mac_2)));
  }

  @Test
  void producesTheSameMacWhenCalculatingTwoConsecutiveMacsForSameContentAndPrivateKeyForStream() {
    // Given
    final MacService macService = new JCAHmacService(HmacAlgorithm.HmacSHA1);

    // When
    final var mac_1 =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            new ByteArrayInputStream(CONTENT));

    final var mac_2 =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(mac_1, is(equalTo(mac_2)));
  }

  @Test
  void producesTheSameMacWhenCalculatingManyConsecutiveMacsForSameContentAndPrivateKeyForByteArray() {
    // Given
    final MacService macService = new JCAHmacService(HmacAlgorithm.HmacSHA1);

    final var _100 = 100;

    // When
    final var generatedMacsSet =
        RunnerUtil.runConsecutively(
            _100,
            () ->
                HexUtil.encodeHex(
                    macService.calculateMac(SECRET_KEY_1234567890123456_128_BITS, CONTENT)));

    // Then
    assertThat(generatedMacsSet, hasSize(1));
  }

  @Test
  void producesTheSameMacWhenCalculatingManyConsecutiveMacsForSameContentAndPrivateKeyForStream() {
    // Given
    final MacService macService = new JCAHmacService(HmacAlgorithm.HmacSHA1);

    final var _100 = 100;

    // When
    final var generatedMacsSet =
        RunnerUtil.runConsecutively(
            _100,
            () ->
                HexUtil.encodeHex(
                    macService.calculateMac(
                        SECRET_KEY_1234567890123456_128_BITS,
                        new ByteArrayInputStream(CONTENT))));

    // Then
    assertThat(generatedMacsSet, hasSize(1));
  }

  @Test
  void producesTheSameMacWhenCalculatingConcurrentlyConsecutiveMacsForSameContentAndPrivateKeyForByteArray() {
    // Given
    final MacService macService = new JCAHmacService(HmacAlgorithm.HmacSHA1);

    final var _500 = 500;

    // When
    final var generatedMacsSet =
        RunnerUtil.runConcurrently(
            _500,
            () ->
                HexUtil.encodeHex(
                    macService.calculateMac(SECRET_KEY_1234567890123456_128_BITS, CONTENT)));

    // Then
    assertThat(generatedMacsSet, hasSize(1));
  }

  @Test
  void producesTheSameMacWhenCalculatingConcurrentlyConsecutiveMacsForSameContentAndPrivateKeyForStream() {
    // Given
    final MacService macService = new JCAHmacService(HmacAlgorithm.HmacSHA1);

    final var _500 = 500;

    // When
    final var generatedMacsSet =
        RunnerUtil.runConcurrently(
            _500,
            () ->
                HexUtil.encodeHex(
                    macService.calculateMac(
                        SECRET_KEY_1234567890123456_128_BITS,
                        new ByteArrayInputStream(CONTENT))));

    // Then
    assertThat(generatedMacsSet, hasSize(1));
  }
}