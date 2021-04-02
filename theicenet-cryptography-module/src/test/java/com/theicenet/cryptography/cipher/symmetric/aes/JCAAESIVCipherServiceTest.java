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

import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.InvalidAuthenticationTagException;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
class JCAAESIVCipherServiceTest {

  static final String AES = "AES";
  static final BlockCipherIVModeOfOperation CBC = BlockCipherIVModeOfOperation.CBC;
  static final BlockCipherIVModeOfOperation CFB = BlockCipherIVModeOfOperation.CFB;
  static final BlockCipherIVModeOfOperation OFB = BlockCipherIVModeOfOperation.OFB;
  static final BlockCipherIVModeOfOperation CTR = BlockCipherIVModeOfOperation.CTR;
  static final BlockCipherIVModeOfOperation GCM = BlockCipherIVModeOfOperation.GCM;

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

  static final byte[] ENCRYPTED_CONTENT_AES_CBC =
      HexUtil.decodeHex(
          "e9ace3b5980b905b3c5823555dbea50b69d0b312"
              + "9f3aa2540255b35dc5d46128a83ae6989e4d94ed"
              + "83d6ffcb4210ddd9686719807ed8537e6040d3cb"
              + "332a63dfe642db91b1e39bad80fa8a86329b04ee"
              + "8ee57305ff62e7daf001897f7c4a1e5a");

  static final byte[] ENCRYPTED_CONTENT_AES_CFB =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc9126d4c171c5e"
              + "fc1c3c7137e9d2fb2f711897b3261d0f760243583"
              + "5a693ab44f52b0e51c889504655b6a88c64c446b6"
              + "669dfc61c082e932ec53767b3de363beb10fa3ceb"
              + "2ed8");

  static final byte[] ENCRYPTED_CONTENT_AES_OFB =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc91263746a29bdf"
              + "2e031c65d44d000366eff30193861a14b73867329d"
              + "a374a511cc52dbfa0fc116f47423ed37694ceb016a"
              + "fd3b208a31e1aa4a7eb99b4f7e57966ec1376588d1");

  static final byte[] ENCRYPTED_CONTENT_AES_CTR =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc9126da73e6"
              + "e016a787a39e6f0bd8914874f6af0f2fca3094"
              + "65217d86aa55d9a1689666ce4189cb6194e1ac"
              + "20e0ea5e2e60ec70b0f31255a4dc6cf304edb41"
              + "92d28c725751474");

  static final byte[] AUTHENTICATION_TAG_GCM =
      HexUtil.decodeHex("ed7f1709863b083e6a7346320f8a5ca9");

  static final byte[] ENCRYPTED_CONTENT_AES_GCM =
      HexUtil.decodeHex(
          "868b0a81b19cc4392191909c349d722395c713a4d3ed3"
              + "5f88b323e5257182434d9c3689057800c25e15b"
              + "143e73ba69fccdc25902183db754e0417928895"
              + "4a78d6a21eb25ca6b5f33054ce19671b7150c9c"
              + "0ea1ea");

  static final byte[] ENCRYPTED_CONTENT_AND_TAG_AES_GCM =
      concat(
          ENCRYPTED_CONTENT_AES_GCM,
          AUTHENTICATION_TAG_GCM);

  @ParameterizedTest
  @EnumSource(BlockCipherIVModeOfOperation.class)
  void producesNotNullWhenEncryptingByteArray(BlockCipherIVModeOfOperation blockMode) {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(BlockCipherIVModeOfOperation.class)
  void producesNotNullWhenEncryptingStream(BlockCipherIVModeOfOperation blockMode) {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray(), is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(BlockCipherIVModeOfOperation.class)
  void producesNotEmptyWhenEncryptingByteArray(BlockCipherIVModeOfOperation blockMode) {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @EnumSource(BlockCipherIVModeOfOperation.class)
  void producesNotEmptyWhenEncryptingByteStream(BlockCipherIVModeOfOperation blockMode) {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @EnumSource(BlockCipherIVModeOfOperation.class)
  void throwsIllegalArgumentExceptionWhenEncryptingByteArrayWithInvalidIVSize(
      BlockCipherIVModeOfOperation blockMode) {
    // Given initialization vector of invalid size (= 64 bits)
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var INITIALIZATION_VECTOR_KLMNOPQR_64_BITS =
        "KLMNOPQR".getBytes(StandardCharsets.UTF_8);

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesCipherService.encrypt( // When encrypting AES with invalid IV size
          SECRET_KEY_1234567890123456_128_BITS,
          INITIALIZATION_VECTOR_KLMNOPQR_64_BITS,
          CLEAR_CONTENT));
  }

  @ParameterizedTest
  @EnumSource(BlockCipherIVModeOfOperation.class)
  void throwsIllegalArgumentExceptionWhenEncryptingStreamWithInvalidIVSize(
      BlockCipherIVModeOfOperation blockMode) {
    // Given initialization vector of invalid size (= 64 bits)
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

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
          encryptedOutputStream));
  }

  @ParameterizedTest
  @EnumSource(
      value = BlockCipherIVModeOfOperation.class,
      names = {"CBC", "GCM"},
      mode = EnumSource.Mode.EXCLUDE)
  void producesSizeOfEncryptedEqualsToSizeOfClearContentWhenEncryptingByteArray(
      BlockCipherIVModeOfOperation blockMode) {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted.length, is(equalTo(CLEAR_CONTENT.length)));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusPaddingWhenEncryptingByteArrayWithBlockModeCBC() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CBC);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(
        encrypted.length,
        is(equalTo(CLEAR_CONTENT.length + (16 - CLEAR_CONTENT.length % 16))));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusAuthenticationTagWhenEncryptingByteArrayWithBlockModeGCM() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(GCM);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(
        encrypted.length,
        is(equalTo(CLEAR_CONTENT.length + AUTHENTICATION_TAG_SIZE_128_BITS / 8)));
  }

  @ParameterizedTest
  @EnumSource(
      value = BlockCipherIVModeOfOperation.class,
      names = {"CBC", "GCM"},
      mode = EnumSource.Mode.EXCLUDE)
  void producesSizeOfEncryptedEqualsToSizeOfClearContentWhenEncryptingStream(
      BlockCipherIVModeOfOperation blockMode) {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray().length, is(is(equalTo(CLEAR_CONTENT.length))));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusPaddingWhenEncryptingStreamWithBlockModeCBC() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CBC);

    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(
        encryptedOutputStream.toByteArray().length,
        is(equalTo(CLEAR_CONTENT.length + (16 - CLEAR_CONTENT.length % 16))));
  }

  @Test
  void producesSizeOfEncryptedEqualsToSizeOfClearContentPlusAuthenticationTagWhenEncryptingStreamWithBlockModeGCM() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(GCM);

    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(
        encryptedOutputStream.toByteArray().length,
        is(equalTo(CLEAR_CONTENT.length + AUTHENTICATION_TAG_SIZE_128_BITS / 8)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithClearContentAndSecretKeyAndIVAndBlockModeAndExpectedEncryptedResult")
  void producesTheRightEncryptedResultWhenEncryptingByteArray(
      byte[] clearContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode,
      byte[] expectedEncryptedResult) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            secretKey,
            iv,
            clearContent);

    // Then
    assertThat(encrypted, is(equalTo(expectedEncryptedResult)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithClearContentAndSecretKeyAndIVAndBlockModeAndExpectedEncryptedResult")
  void producesTheRightEncryptedResultWhenEncryptingStream(
      byte[] clearContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode,
      byte[] expectedEncryptedResult) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var clearInputStream = new ByteArrayInputStream(clearContent);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.encrypt(
        secretKey,
        iv,
        clearInputStream,
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray(), is(equalTo(expectedEncryptedResult)));
  }

  static Stream<Arguments> argumentsWithClearContentAndSecretKeyAndIVAndBlockModeAndExpectedEncryptedResult() {
    return Stream.of(
        Arguments.of(
            CLEAR_CONTENT,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CBC,
            ENCRYPTED_CONTENT_AES_CBC),
        Arguments.of(
            CLEAR_CONTENT,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CFB,
            ENCRYPTED_CONTENT_AES_CFB),
        Arguments.of(
            CLEAR_CONTENT,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            OFB,
            ENCRYPTED_CONTENT_AES_OFB),
        Arguments.of(
            CLEAR_CONTENT,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CTR,
            ENCRYPTED_CONTENT_AES_CTR),
        Arguments.of(
            CLEAR_CONTENT,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            GCM,
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM)
    );
  }

  @Test
  void producesSameEncryptedWhenEncryptingTwoConsecutiveTimesTheSameContentWithTheSameKeyAndIVForByteArray() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    // When
    final var encrypted_1 =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    final var encrypted_2 =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted_1, is(equalTo(encrypted_2)));
  }

  @Test
  void producesSameEncryptedWhenEncryptingTwoConsecutiveTimesTheSameContentWithTheSameKeyAndIVForStream() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    // When
    final var clearInputStream_1 = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream_1 = new ByteArrayOutputStream();
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream_1,
        encryptedOutputStream_1);

    final var clearInputStream_2 = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream_2 = new ByteArrayOutputStream();
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        clearInputStream_2,
        encryptedOutputStream_2);

    // Then
    assertThat(encryptedOutputStream_1.toByteArray(), is(equalTo(encryptedOutputStream_2.toByteArray())));
  }

  @Test
  void producesSameEncryptedWhenEncryptingManyConsecutiveTimesTheSameContentWithTheSameKeyAndIVForByteArray() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

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
                        CLEAR_CONTENT)));

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingManyConsecutiveTimesTheSameContentWithTheSameKeyAndIVForStream() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

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
                  encryptedOutputStream);

              return HexUtil.encodeHex(encryptedOutputStream.toByteArray());
            });

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingConcurrentlyManyTimesTheSameContentWithTheSameKeyAndIVForByteArray() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    final var _500 = 500;

    // When
    final var encryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> HexUtil.encodeHex(
                aesCipherService.encrypt(
                    SECRET_KEY_1234567890123456_128_BITS,
                    INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                    CLEAR_CONTENT)));

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @Test
  void producesSameEncryptedWhenEncryptingConcurrentlyManyTimesTheSameContentWithTheSameKeyAndIVForStream() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

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
                  encryptedOutputStream);

              return HexUtil.encodeHex(encryptedOutputStream.toByteArray());
            });

    // Then
    assertThat(encryptedSet, hasSize(1));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesNotNullWhenDecryptingByteArray(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var decrypted =
        aesCipherService.decrypt(
            secretKey,
            iv,
            encryptedContent);

    // Then
    assertThat(decrypted, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesNotNullWhenDecryptingStream(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var encryptedInputStream = new ByteArrayInputStream(encryptedContent);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        secretKey,
        iv,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesNotEmptyWhenDecryptingByteArray(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var decrypted =
        aesCipherService.decrypt(
            secretKey,
            iv,
            encryptedContent);

    // Then
    assertThat(decrypted.length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesNotEmptyWhenDecryptingStream(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var encryptedInputStream = new ByteArrayInputStream(encryptedContent);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        secretKey,
        iv,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void throwsIllegalArgumentExceptionWhenDecryptingByteArrayWithInvalidIVSize(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode) {

    // Given initialization vector of invalid size (= 64 bits)
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var INITIALIZATION_VECTOR_KLMNOPQR_64_BITS =
        "KLMNOPQR".getBytes(StandardCharsets.UTF_8);

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesCipherService.decrypt( // When decrypting AES with invalid IV size
          secretKey,
          INITIALIZATION_VECTOR_KLMNOPQR_64_BITS,
          encryptedContent));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void throwsIllegalArgumentExceptionWhenDecryptingStreamWithInvalidIVSize(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode) {

    // Given initialization vector of invalid size (= 64 bits)
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var INITIALIZATION_VECTOR_KLMNOPQR_64_BITS =
        "KLMNOPQR".getBytes(StandardCharsets.UTF_8);

    final var encryptedInputStream = new ByteArrayInputStream(encryptedContent);
    final var clearOutputStream = new ByteArrayOutputStream();

    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () ->
      aesCipherService.decrypt( // When decrypting AES with invalid IV size
          secretKey,
          INITIALIZATION_VECTOR_KLMNOPQR_64_BITS,
          encryptedInputStream,
          clearOutputStream));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesSizeOfDecryptedEqualsToSizeOfClearContentWhenDecryptingByteArray(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode,
      byte[] expectedDecryptedResult) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var decrypted =
        aesCipherService.decrypt(
            secretKey,
            iv,
            encryptedContent);

    // Then
    assertThat(decrypted.length, is(equalTo(expectedDecryptedResult.length)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesSizeOfDecryptedEqualsToSizeOfClearContentWhenDecryptingStream(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode,
      byte[] expectedDecryptedResult) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var encryptedInputStream = new ByteArrayInputStream(encryptedContent);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        secretKey,
        iv,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(expectedDecryptedResult.length)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesTheRightDecryptedResultWhenDecryptingByteArray(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode,
      byte[] expectedDecryptedResult) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    // When
    final var decrypted =
        aesCipherService.decrypt(
            secretKey,
            iv,
            encryptedContent);

    // Then
    assertThat(decrypted, is(equalTo(expectedDecryptedResult)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult")
  void producesTheRightDecryptedResultWhenDecryptingStream(
      byte[] encryptedContent,
      SecretKey secretKey,
      byte[] iv,
      BlockCipherIVModeOfOperation blockMode,
      byte[] expectedDecryptedResult) {

    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(blockMode);

    final var encryptedInputStream = new ByteArrayInputStream(encryptedContent);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        secretKey,
        iv,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(equalTo(expectedDecryptedResult)));
  }

  static Stream<Arguments> argumentsWithEncryptedContentAndSecretKeyAndIVAndBlockModeAndExpectedDecryptedResult() {
    return Stream.of(
        Arguments.of(
            ENCRYPTED_CONTENT_AES_CBC,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CBC,
            CLEAR_CONTENT),
        Arguments.of(
            ENCRYPTED_CONTENT_AES_CFB,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CFB,
            CLEAR_CONTENT),
        Arguments.of(
            ENCRYPTED_CONTENT_AES_OFB,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            OFB,
            CLEAR_CONTENT),
        Arguments.of(
            ENCRYPTED_CONTENT_AES_CTR,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CTR,
            CLEAR_CONTENT),
        Arguments.of(
            ENCRYPTED_CONTENT_AND_TAG_AES_GCM,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            GCM,
            CLEAR_CONTENT)
    );
  }

  @Test
  void throwsExceptionWhenDecryptingByteArrayAndBlockModeGCMAndAuthenticationTagHasBeenManipulated() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(GCM);

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
                MANIPULATED_ENCRYPTED_AND_TAG));
  }

  @Test
  void producesEmptyToOutputWhenDecryptingStreamAndBlockModeGCMAndAuthenticationTagHasBeenManipulated() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(GCM);

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
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(0)));
  }

  @Test
  void throwsExceptionWhenDecryptingByteArrayAndBlockModeGCMAndEncryptedHasBeenManipulated() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(GCM);

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
                MANIPULATED_ENCRYPTED_AND_TAG));
  }

  @Test
  void producesEmptyToOutputWhenDecryptingStreamAndBlockModeGCMAndEncryptedHasBeenManipulated() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(GCM);

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
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray().length, is(equalTo(0)));
  }

  @Test
  void producesSameClearContentWhenDecryptingTwoConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVForByteArray() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    // When
    final var decrypted_1 =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CTR);

    final var decrypted_2 =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CTR);

    // Then
    assertThat(decrypted_1, is(equalTo(decrypted_2)));
  }

  @Test
  void producesSameClearContentWhenDecryptingTwoConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVForStream() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    // When
    final var encryptedInputStream_1 = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_CTR);
    final var clearContentOutputStream_1 = new ByteArrayOutputStream();
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream_1,
        clearContentOutputStream_1);

    final var encryptedInputStream_2 = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_CTR);
    final var clearContentOutputStream_2 = new ByteArrayOutputStream();
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream_2,
        clearContentOutputStream_2);

    // Then
    assertThat(
        clearContentOutputStream_1.toByteArray(),
        is(equalTo(
            clearContentOutputStream_2.toByteArray())));
  }

  @Test
  void producesSameClearContentWhenDecryptingManyConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVForByteArray() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

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
                        ENCRYPTED_CONTENT_AES_CTR)));

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingManyConsecutiveTimesTheSameEncryptedWithTheSameKeyAndIVForStream() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    final var _100 = 100;

    // When
    final var decryptedSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () -> {
              final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_CTR);
              final var clearContentOutputStream = new ByteArrayOutputStream();

              aesCipherService.decrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                  encryptedInputStream,
                  clearContentOutputStream);

              return HexUtil.encodeHex(clearContentOutputStream.toByteArray());
            });

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingConcurrentlyManyTimesTheSameEncryptedWithTheSameKeyAndIVForByteArray() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    final var _500 = 500;

    // When
    final var decryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> HexUtil.encodeHex(
                aesCipherService.decrypt(
                    SECRET_KEY_1234567890123456_128_BITS,
                    INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                    ENCRYPTED_CONTENT_AES_CTR)));

    // Then
    assertThat(decryptedSet, hasSize(1));
  }

  @Test
  void producesSameClearContentWhenDecryptingConcurrentlyManyTimesTheSameEncryptedWithTheSameKeyAndIVForStream() {
    // Given
    final SymmetricIVCipherService aesCipherService = new JCAAESIVCipherService(CTR);

    final var _500 = 500;

    // When
    final var decryptedSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () -> {
              final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_CTR);
              final var clearContentOutputStream = new ByteArrayOutputStream();

              aesCipherService.decrypt(
                  SECRET_KEY_1234567890123456_128_BITS,
                  INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                  encryptedInputStream,
                  clearContentOutputStream);

              return HexUtil.encodeHex(clearContentOutputStream.toByteArray());
            });

    // Then
    assertThat(decryptedSet, hasSize(1));
  }
}

