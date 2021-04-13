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
package com.theicenet.cryptography.key.symmetric.aes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import com.theicenet.cryptography.random.JCASecureRandomDataService;
import com.theicenet.cryptography.random.SecureRandomAlgorithm;
import com.theicenet.cryptography.random.SecureRandomDataService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Juan Fidalgo
 */
class JCAAESKeyServiceTest {

  final int KEY_LENGTH_128_BITS = 128;
  final int KEY_LENGTH_256_BITS = 256;
  final String AES = "AES";
  final String RAW = "RAW";

  final SecureRandomDataService secureRandomDataService =
      new JCASecureRandomDataService(SecureRandomAlgorithm.DEFAULT); // This is not mocked, because JCAAESKeyService must use the SecureRandom embedded in SecureRandomDataService, so a real instance is created and the component is fully tested. SecureRandomDataService acts only as a container for the library's SecureRandom


  SymmetricKeyService aesKeyService;

  @BeforeEach
  void setUp() {
    aesKeyService = new JCAAESKeyService(secureRandomDataService);
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndInvalidKeyLength() {
    // Given
    final var KEY_LENGTH_MINUS_ONE = -1;

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesKeyService.generateKey(KEY_LENGTH_MINUS_ONE)); // When generating key and invalid key length
  }

  @Test
  void producesNotNullWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(256);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @Test
  void producesKeyWithAESAlgorithmWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(AES)));
  }

  @Test
  void producesKeyWithRAWFormatWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo(RAW)));
  }

  @ParameterizedTest
  @ValueSource(ints = {
      KEY_LENGTH_128_BITS,
      KEY_LENGTH_256_BITS})
  void producesKeyWithTheRequestLengthWhenGeneratingKey(int keyLength) {
    // When
    final var generatedKey = aesKeyService.generateKey(keyLength);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(keyLength)));
  }

  @Test
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength() {
    // When generating two consecutive keys with the same length
    final var generatedKey_1 = aesKeyService.generateKey(KEY_LENGTH_128_BITS);
    final var generatedKey_2 = aesKeyService.generateKey(KEY_LENGTH_128_BITS);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @Test
  void producesDifferentKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength() {
    // Given
    final var _100 = 100;

    // When generating consecutive keys with the same length
    final var generatedKeysSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    aesKeyService
                        .generateKey(KEY_LENGTH_128_BITS)
                        .getEncoded()));

    // Then all keys have been generated and all them are different
    assertThat(generatedKeysSet, hasSize(_100));
  }

  @Test
  void producesDifferentKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength() throws Exception {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time random keys with the same length
    final var generatedKeysSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    aesKeyService
                        .generateKey(KEY_LENGTH_128_BITS)
                        .getEncoded()));

    // Then all keys have been generated and all them are different
    assertThat(generatedKeysSet, hasSize(_500));
  }
}
