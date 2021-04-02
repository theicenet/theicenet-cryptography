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

import static com.theicenet.cryptography.util.ByteArraysUtil.concat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.cipher.symmetric.BlockCipherAEADModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.InvalidAuthenticationTagException;
import com.theicenet.cryptography.cipher.symmetric.SymmetricAEADCipherService;
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
class JCAAESAEADCipherServiceTest {

  static final String AES = "AES";
  static final BlockCipherAEADModeOfOperation GCM = BlockCipherAEADModeOfOperation.GCM;

  final int AUTHENTICATION_TAG_SIZE_128_BITS = 128;

  static final byte[] CLEAR_CONTENT =
      "Content to encrypt with AES and different options for block cipher mode of operation"
          .getBytes(StandardCharsets.UTF_8);

  static final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  static final byte[] INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS =
      "KLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  static final byte[] ASSOCIATED_DATA_1 = "Associated data one.".getBytes(StandardCharsets.UTF_8);
  static final byte[] ASSOCIATED_DATA_2 = "Associated data two.".getBytes(StandardCharsets.UTF_8);

  static final byte[] AUTHENTICATION_TAG_GCM =
      HexUtil.decodeHex("ded15a2d500fcd26a9501be9cef83a17");

  static final byte[] ENCRYPTED_CONTENT_AES_GCM =
      HexUtil.decodeHex(
          "868b0a81b19cc4392191909c349d722395c713a4d3ed35f88b32"
              + "3e5257182434d9c3689057800c25e15b143e73ba69fccd"
              + "c25902183db754e04179288954a78d6a21eb25ca6b5f33"
              + "054ce19671b7150c9c0ea1ea");


  static final byte[] ENCRYPTED_CONTENT_AND_TAG_AES_GCM =
      concat(
          ENCRYPTED_CONTENT_AES_GCM,
          AUTHENTICATION_TAG_GCM);

  SymmetricAEADCipherService aesCipherService;

  @BeforeEach
  void setUp() {
    aesCipherService = new JCAAESAEADCipherService(GCM);
  }

  @Test
  void producesNotNullWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

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
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(encryptedOutputStream.toByteArray(), is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

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
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(encryptedOutputStream.toByteArray().length, is(greaterThan(0)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenEncryptingByteArrayWithInvalidIVSize() {
    // Given initialization vector of invalid size (= 64 bits)
    final var INITIALIZATION_VECTOR_KLMNOPQR_64_BITS =
        "KLMNOPQR".getBytes(StandardCharsets.UTF_8);

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesCipherService.encrypt( // When encrypting AES with invalid IV size
          SECRET_KEY_1234567890123456_128_BITS,
          INITIALIZATION_VECTOR_KLMNOPQR_64_BITS,
          CLEAR_CONTENT,
          ASSOCIATED_DATA_1,
          ASSOCIATED_DATA_2));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenEncryptingStreamWithInvalidIVSize() {
    // Given initialization vector of invalid size (= 64 bits)
    final var INITIALIZATION_VECTOR_KLMNOPQR_64_BITS =
        "KLMNOPQR".getBytes(StandardCharsets.UTF_8);

    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesCipherService.encrypt( // When encrypting AES with invalid IV size
          SECRET_KEY_1234567890123456_128_BITS,
          INITIALIZATION_VECTOR_KLMNOPQR_64_BITS,
          clearInputStream,
          encryptedOutputStream,
          ASSOCIATED_DATA_1,
          ASSOCIATED_DATA_2));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusAuthenticationTagWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(
        encrypted.length,
        is(equalTo(CLEAR_CONTENT.length + AUTHENTICATION_TAG_SIZE_128_BITS / 8)));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusAuthenticationTagWhenEncryptingStream() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(
        encryptedOutputStream.toByteArray().length,
        is(equalTo(CLEAR_CONTENT.length + AUTHENTICATION_TAG_SIZE_128_BITS / 8)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AND_TAG_AES_GCM)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingStream() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(
        encryptedOutputStream.toByteArray(),
        is(equalTo(ENCRYPTED_CONTENT_AND_TAG_AES_GCM)));
  }

  @Test
  void producesSameEncryptedWhenEncryptingTwoConsecutiveTimesTheSameContentWithTheSameKeyAndIVAndADForByteArray() {
    // When
    final var encrypted_1 =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    final var encrypted_2 =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(encrypted_1, is(equalTo(encrypted_2)));
  }

  @Test
  void producesSameEncryptedWhenEncryptingTwoConsecutiveTimesTheSameContentWithTheSameKeyAndIVAndADForStream() {
    // When
    final var clearInputStream_1 = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream_1 = new ByteArrayOutputStream();
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream_1,
        encryptedOutputStream_1,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    final var clearInputStream_2 = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream_2 = new ByteArrayOutputStream();
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream_2,
        encryptedOutputStream_2,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(encryptedOutputStream_1.toByteArray(), is(equalTo(encryptedOutputStream_2.toByteArray())));
  }

  @Test
  void producesSameEncryptedWhenEncryptingManyConsecutiveTimesTheSameContentWithTheSameKeyAndIVAndADForByteArray() {
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
                        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                        CLEAR_CONTENT,
                        ASSOCIATED_DATA_1,
                        ASSOCIATED_DATA_2)));

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingManyConsecutiveTimesTheSameContentWithTheSameKeyAndIVAndADForStream() {
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
                  INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                  clearInputStream,
                  encryptedOutputStream,
                  ASSOCIATED_DATA_1,
                  ASSOCIATED_DATA_2);

              return HexUtil.encodeHex(encryptedOutputStream.toByteArray());
            });

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingConcurrentlyManyTimesTheSameContentWithTheSameKeyAndIVAndADForByteArray() {
    // Given
    final var _500 = 500;

    // When
    final var encryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> HexUtil.encodeHex(
                aesCipherService.encrypt(
                    SECRET_KEY_1234567890123456_128_BITS,
                    INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                    CLEAR_CONTENT,
                    ASSOCIATED_DATA_1,
                    ASSOCIATED_DATA_2)));

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingConcurrentlyManyTimesTheSameContentWithTheSameKeyAndIVAndADForStream() {
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
                  INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                  clearInputStream,
                  encryptedOutputStream,
                  ASSOCIATED_DATA_1,
                  ASSOCIATED_DATA_2);

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
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(decrypted, is(notNullValue()));
  }

  @Test
  void producesNotNullWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(decrypted.length, is(greaterThan(0)));
  }

  @Test
  void producesNotEmptyWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(greaterThan(0)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenDecryptingByteArrayWithInvalidIVSize() {
    // Given initialization vector of invalid size (= 64 bits)
    final var INITIALIZATION_VECTOR_KLMNOPQR_64_BITS =
        "KLMNOPQR".getBytes(StandardCharsets.UTF_8);

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesCipherService.decrypt( // When decrypting AES with invalid IV size
          SECRET_KEY_1234567890123456_128_BITS,
          INITIALIZATION_VECTOR_KLMNOPQR_64_BITS,
          ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
          ASSOCIATED_DATA_1,
          ASSOCIATED_DATA_2));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenDecryptingStreamWithInvalidIVSize() {
    // Given initialization vector of invalid size (= 64 bits)
    final var INITIALIZATION_VECTOR_KLMNOPQR_64_BITS =
        "KLMNOPQR".getBytes(StandardCharsets.UTF_8);

    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);

    final var clearOutputStream = new ByteArrayOutputStream();

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesCipherService.decrypt( // When decrypting AES with invalid IV size
          SECRET_KEY_1234567890123456_128_BITS,
          INITIALIZATION_VECTOR_KLMNOPQR_64_BITS,
          encryptedInputStream,
          clearOutputStream,
          ASSOCIATED_DATA_1,
          ASSOCIATED_DATA_2));
  }

  @Test
  void producesSizeOfDecryptedEqualsToSizeOfClearContentWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(decrypted.length, is(equalTo(CLEAR_CONTENT.length)));
  }

  @Test
  void producesSizeOfDecryptedEqualsToSizeOfClearContentWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(CLEAR_CONTENT.length)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(equalTo(CLEAR_CONTENT)));
  }
  
  @Test
  void throwsExceptionWhenDecryptingByteArrayAndAuthenticationTagHasBeenManipulated() {
    // Given
    byte[] MANIPULATED_AUTHENTICATION_TAG = AUTHENTICATION_TAG_GCM.clone();
    MANIPULATED_AUTHENTICATION_TAG[0] += 1;

    final byte[] MANIPULATED_ENCRYPTED_AND_TAG =
        concat(ENCRYPTED_CONTENT_AES_GCM, MANIPULATED_AUTHENTICATION_TAG);

    // Then
    assertThrows(
        InvalidAuthenticationTagException.class,
        () ->
            aesCipherService.decrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                MANIPULATED_ENCRYPTED_AND_TAG,
                ASSOCIATED_DATA_1,
                ASSOCIATED_DATA_2));
  }

  @Test
  void producesEmptyToOutputWhenDecryptingStreamAndAuthenticationTagHasBeenManipulated() {
    // Given
    byte[] MANIPULATED_AUTHENTICATION_TAG = AUTHENTICATION_TAG_GCM.clone();
    MANIPULATED_AUTHENTICATION_TAG[0] += 1;

    final var encryptedInputStream =
        new ByteArrayInputStream(concat(ENCRYPTED_CONTENT_AES_GCM, MANIPULATED_AUTHENTICATION_TAG));

    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(0)));
  }

  @Test
  void throwsExceptionWhenDecryptingByteArrayAndAuthenticationTagIsNotProvided() {
    // Then
    assertThrows(
        InvalidAuthenticationTagException.class,
        () ->
            aesCipherService.decrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                ENCRYPTED_CONTENT_AND_TAG_AES_GCM));
  }

  @Test
  void producesEmptyToOutputWhenDecryptingStreamAndAuthenticationTagIsNotProvided() {
    // Given
    final var encryptedInputStream =
        new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);

    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(0)));
  }

  @Test
  void throwsExceptionWhenDecryptingByteArrayAndEncryptedHasBeenManipulated() {
    // Given
    byte[] MANIPULATED_ENCRYPTED = ENCRYPTED_CONTENT_AES_GCM.clone();
    MANIPULATED_ENCRYPTED[0] += 1;

    final byte[] MANIPULATED_ENCRYPTED_AND_TAG =
        concat(MANIPULATED_ENCRYPTED, AUTHENTICATION_TAG_GCM);

    // Then
    assertThrows(
        InvalidAuthenticationTagException.class,
        () ->
            aesCipherService.decrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                MANIPULATED_ENCRYPTED_AND_TAG,
                ASSOCIATED_DATA_1,
                ASSOCIATED_DATA_2));
  }

  @Test
  void producesEmptyToOutputWhenDecryptingStreamAndEncryptedHasBeenManipulated() {
    // Given
    byte[] MANIPULATED_ENCRYPTED = ENCRYPTED_CONTENT_AES_GCM.clone();
    MANIPULATED_ENCRYPTED[0] += 1;

    final var encryptedInputStream =
        new ByteArrayInputStream(concat(MANIPULATED_ENCRYPTED, AUTHENTICATION_TAG_GCM));

    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(0)));
  }

  @Test
  void producesSameClearContentWhenDecryptingTwoConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVAndADForByteArray() {
    // When
    final var decrypted_1 =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    final var decrypted_2 =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(decrypted_1, is(equalTo(decrypted_2)));
  }

  @Test
  void producesSameClearContentWhenDecryptingTwoConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVAndADForStream() {
    // When
    final var encryptedInputStream_1 = new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
    final var clearContentOutputStream_1 = new ByteArrayOutputStream();
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream_1,
        clearContentOutputStream_1,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    final var encryptedInputStream_2 = new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
    final var clearContentOutputStream_2 = new ByteArrayOutputStream();
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream_2,
        clearContentOutputStream_2,
        ASSOCIATED_DATA_1,
        ASSOCIATED_DATA_2);

    // Then
    assertThat(
        clearContentOutputStream_1.toByteArray(),
        is(equalTo(
            clearContentOutputStream_2.toByteArray())));
  }

  @Test
  void producesSameClearContentWhenDecryptingManyConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVAndADForByteArray() {
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
                        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                        ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
                        ASSOCIATED_DATA_1,
                        ASSOCIATED_DATA_2)));

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingManyConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVAndADForStream() {
    // Given
    final var _100 = 100;

    // When
    final var decryptedSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> {
              final var encryptedInputStream =
                  new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
              final var clearContentOutputStream = new ByteArrayOutputStream();

              aesCipherService.decrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                  encryptedInputStream,
                  clearContentOutputStream,
                  ASSOCIATED_DATA_1,
                  ASSOCIATED_DATA_2);

              return HexUtil.encodeHex(clearContentOutputStream.toByteArray());
            });

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingConcurrentlyManyTimesTheSameEncryptedWithTheSameKeyAndIVAndADForByteArray() {
    // Given
    final var _500 = 500;

    // When
    final var decryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> HexUtil.encodeHex(
                aesCipherService.decrypt(
                    SECRET_KEY_1234567890123456_128_BITS,
                    INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                    ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
                    ASSOCIATED_DATA_1,
                    ASSOCIATED_DATA_2)));

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingConcurrentlyManyTimesTheSameEncryptedWithTheSameKeyAndIVAndADForStream() {
    // Given
    final var _500 = 500;

    // When
    final var decryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> {
              final var encryptedInputStream =
                  new ByteArrayInputStream(ENCRYPTED_CONTENT_AND_TAG_AES_GCM);
              final var clearContentOutputStream = new ByteArrayOutputStream();

              aesCipherService.decrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                  encryptedInputStream,
                  clearContentOutputStream,
                  ASSOCIATED_DATA_1,
                  ASSOCIATED_DATA_2);

              return HexUtil.encodeHex(clearContentOutputStream.toByteArray());
            });

    // Then
    assertThat(decryptedSet, hasSize(1));
  }
}

