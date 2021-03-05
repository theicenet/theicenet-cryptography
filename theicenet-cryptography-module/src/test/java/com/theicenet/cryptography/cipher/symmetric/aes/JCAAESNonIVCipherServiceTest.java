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
package com.theicenet.cryptography.cipher.symmetric.aes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;

import com.theicenet.cryptography.cipher.symmetric.BlockCipherNonIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVCipherService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class JCAAESNonIVCipherServiceTest {
  // Given
  final String AES = "AES";

  final byte[] CLEAR_CONTENT =
      "Content to encrypt with AES and different options for block cipher mode of operation"
          .getBytes(StandardCharsets.UTF_8);

  final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  final byte[] ENCRYPTED_CONTENT_AES_ECB =
      HexUtil.decodeHex(
          "1f28432db0cb9a41a18068300e9731fc816b36e9b78d803e8ad1d7828ab8c"
              + "eef25722793b8c8e0b3a4c72f12ded24ea264d2c988f17d8d44c249"
              + "b3f8e588b41a7ab826fc440227e99ae6e1df2d50b4b00fce059bc32"
              + "c93e9fd7c5938327e38ab");

  SymmetricNonIVCipherService aesCipherService;

  @BeforeEach
  void setUp() {
    aesCipherService = new JCAAESNonIVCipherService(BlockCipherNonIVModeOfOperation.ECB);
  }

  @Test
  void producesNotNullWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(notNullValue()));
  }

  @Test
  void producesNotNullWhenEncryptingStream() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray(), is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted.length, is(greaterThan(0)));
  }

  @Test
  void producesNotEmptyWhenEncryptingByteStream() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray().length, is(greaterThan(0)));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusPaddingWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(
        encrypted.length,
        is(equalTo(CLEAR_CONTENT.length + (16 - CLEAR_CONTENT.length % 16))));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusPaddingWhenEncryptingStream() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(
        encryptedOutputStream.toByteArray().length,
        is(equalTo(CLEAR_CONTENT.length + (16 - CLEAR_CONTENT.length % 16))));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_ECB)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingStream() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray(), is(equalTo(ENCRYPTED_CONTENT_AES_ECB)));
  }

  @Test
  void producesSameEncryptedWhenEncryptingTwoConsecutiveTimesTheSameContentWithTheSameKeyForByteArray() {
    // When
    final var encrypted_1 =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    final var encrypted_2 =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted_1, is(equalTo(encrypted_2)));
  }

  @Test
  void producesSameEncryptedWhenEncryptingTwoConsecutiveTimesTheSameContentWithTheSameKeyForStream() {
    // When
    final var clearInputStream_1 = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream_1 = new ByteArrayOutputStream();
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream_1,
        encryptedOutputStream_1);

    final var clearInputStream_2 = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream_2 = new ByteArrayOutputStream();
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream_2,
        encryptedOutputStream_2);

    // Then
    assertThat(encryptedOutputStream_1.toByteArray(), is(equalTo(encryptedOutputStream_2.toByteArray())));
  }

  @Test
  void producesSameEncryptedWhenEncryptingManyConsecutiveTimesTheSameContentWithTheSameKeyForByteArray() {
    // Given
    final var _100 = 100;

    // When
    final var encryptedSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    aesCipherService.encrypt(
                        SECRET_KEY_1234567890123456_128_BITS,
                        CLEAR_CONTENT)));

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingManyConsecutiveTimesTheSameContentWithTheSameKeyForStream() {
    // Given
    final var _100 = 100;

    // When
    final var encryptedSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> {
              final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
              final var encryptedOutputStream = new ByteArrayOutputStream();

              aesCipherService.encrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  clearInputStream,
                  encryptedOutputStream);

              return HexUtil.encodeHex(encryptedOutputStream.toByteArray());
            });

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingConcurrentlyManyTimesTheSameContentWithTheSameKeyForByteArray() {
    // Given
    final var _500 = 500;

    // When
    final var encryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> HexUtil.encodeHex(
                aesCipherService.encrypt(
                    SECRET_KEY_1234567890123456_128_BITS,
                    CLEAR_CONTENT)));

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingConcurrentlyManyTimesTheSameContentWithTheSameKeyForStream() {
    // Given
    final var _500 = 500;

    // When
    final var encryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> {
              final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
              final var encryptedOutputStream = new ByteArrayOutputStream();

              aesCipherService.encrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  clearInputStream,
                  encryptedOutputStream);

              return HexUtil.encodeHex(encryptedOutputStream.toByteArray());
            });

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesNotNullWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    // Then
    assertThat(decrypted, is(notNullValue()));
  }

  @Test
  void producesNotNullWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    // Then
    assertThat(decrypted.length, is(greaterThan(0)));
  }

  @Test
  void producesNotEmptyWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(greaterThan(0)));
  }

  @Test
  void producesSizeOfDecryptedEqualsToSizeOfClearContentWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    // Then
    assertThat(decrypted.length, is(equalTo(CLEAR_CONTENT.length)));
  }

  @Test
  void producesSizeOfDecryptedEqualsToSizeOfClearContentWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(CLEAR_CONTENT.length)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesSameClearContentWhenDecryptingTwoConsecutiveTimesTheSameEncryptedWithTheSameKeyForByteArray() {
    // When
    final var decrypted_1 =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    final var decrypted_2 =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    // Then
    assertThat(decrypted_1, is(equalTo(decrypted_2)));
  }

  @Test
  void producesSameClearContentWhenDecryptingTwoConsecutiveTimesTheSameEncryptedWithTheSameKeyForStream() {
    // When
    final var encryptedInputStream_1 = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
    final var clearContentOutputStream_1 = new ByteArrayOutputStream();
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream_1,
        clearContentOutputStream_1);

    final var encryptedInputStream_2 = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
    final var clearContentOutputStream_2 = new ByteArrayOutputStream();
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream_2,
        clearContentOutputStream_2);

    // Then
    assertThat(clearContentOutputStream_1.toByteArray(), is(equalTo(clearContentOutputStream_2.toByteArray())));
  }

  @Test
  void producesSameClearContentWhenDecryptingManyConsecutiveTimesTheSameEncryptedWithTheSameKeyForByteArray() {
    // Given
    final var _100 = 100;

    // When
    final var decryptedSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    aesCipherService.decrypt(
                        SECRET_KEY_1234567890123456_128_BITS,
                        ENCRYPTED_CONTENT_AES_ECB)));

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingManyConsecutiveTimesTheSameEncryptedWithTheSameKeyForStream() {
    // Given
    final var _100 = 100;

    // When
    final var decryptedSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> {
              final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
              final var clearContentOutputStream = new ByteArrayOutputStream();

              aesCipherService.decrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  encryptedInputStream,
                  clearContentOutputStream);

              return HexUtil.encodeHex(clearContentOutputStream.toByteArray());
            });

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingConcurrentlyManyTimesTheSameEncryptedWithTheSameKeyForByteArray() {
    // Given
    final var _500 = 500;

    // When
    final var decryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> HexUtil.encodeHex(
                aesCipherService.decrypt(
                    SECRET_KEY_1234567890123456_128_BITS,
                    ENCRYPTED_CONTENT_AES_ECB)));

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingConcurrentlyManyTimesTheSameEncryptedWithTheSameKeyForStream() {
    // Given
    final var _500 = 500;

    // When
    final var decryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> {
              final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_ECB);
              final var clearContentOutputStream = new ByteArrayOutputStream();

              aesCipherService.decrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  encryptedInputStream,
                  clearContentOutputStream);

              return HexUtil.encodeHex(clearContentOutputStream.toByteArray());
            });

    // Then
    assertThat(decryptedSet, hasSize(1));
  }
}