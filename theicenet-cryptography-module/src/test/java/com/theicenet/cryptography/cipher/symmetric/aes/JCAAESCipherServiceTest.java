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
package com.theicenet.cryptography.cipher.symmetric.aes;

import static com.theicenet.cryptography.util.ByteArraysUtil.concat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherNonIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVCipherService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import com.theicenet.cryptography.test.support.HexUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Juan Fidalgo
 */
@ExtendWith(MockitoExtension.class)
class JCAAESCipherServiceTest {

  static final String AES = "AES";

  static final BlockCipherNonIVModeOfOperation ECB = BlockCipherNonIVModeOfOperation.ECB;
  static final BlockCipherIVModeOfOperation CBC = BlockCipherIVModeOfOperation.CBC;

  static final byte[] CLEAR_CONTENT =
      "Content to encrypt with AES and different options for block cipher mode of operation"
          .getBytes(StandardCharsets.UTF_8);

  static final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  static final byte[] INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS =
      "KLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  static final byte[] ENCRYPTED_CONTENT_AES =
      HexUtil.decodeHex(
          "e9ace3b5980b905b3c5823555dbea50b69d0b312"
              + "9f3aa2540255b35dc5d46128a83ae6989e4d94ed"
              + "83d6ffcb4210ddd9686719807ed8537e6040d3cb"
              + "332a63dfe642db91b1e39bad80fa8a86329b04ee"
              + "8ee57305ff62e7daf001897f7c4a1e5a");

  @Mock
  SymmetricNonIVCipherService aesNonIVCipherService;

  @Mock
  SymmetricIVCipherService aesIVCipherService;

  @Mock
  SecureRandomDataService randomDataService;

  @Mock
  InputStream clearInputStream;

  @Mock
  OutputStream encryptedOutputStream;

  @Mock
  InputStream encryptedContentInputStream;

  @Mock
  OutputStream clearContentOutputStream;

  @Test
  void throwsNullPointerExceptionWhenEncryptingByteArrayAndNullSecretKeyAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.encrypt(NULL_SECRET_KEY, CLEAR_CONTENT));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingByteArrayAndNullSecretKeyAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.encrypt(NULL_SECRET_KEY, CLEAR_CONTENT));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingByteArrayAndNullClearContentAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final byte[] NULL_CLEAR_CONTENT = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.encrypt(SECRET_KEY_1234567890123456_128_BITS, NULL_CLEAR_CONTENT));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingByteArrayAndNullClearContentAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final byte[] NULL_CLEAR_CONTENT = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.encrypt(SECRET_KEY_1234567890123456_128_BITS, NULL_CLEAR_CONTENT));
  }

  @Test
  void producesNotNullWhenEncryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.encrypt(SECRET_KEY_1234567890123456_128_BITS, CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenEncryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.encrypt(SECRET_KEY_1234567890123456_128_BITS, CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted.length, is(greaterThan(0)));
  }

  @Test
  void producesTheRightResultWhenEncryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.encrypt(SECRET_KEY_1234567890123456_128_BITS, CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES)));
  }

  @Test
  void ignoresIVCipherWhenEncryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.encrypt(SECRET_KEY_1234567890123456_128_BITS, CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    verify(aesIVCipherService, never()).encrypt(any(), any(), any());
  }

  @Test
  void producesNotNullWhenEncryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);
    when(
        aesIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenEncryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);
    when(
        aesIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted.length, is(greaterThan(0)));
  }

  @Test
  void producesTheRightResultWhenEncryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);
    when(
        aesIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(
        encrypted,
        is(equalTo(
            concat(
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                ENCRYPTED_CONTENT_AES))));
  }

  @Test
  void ignoresNonIVCipherWhenEncryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);
    when(
        aesIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    verify(aesNonIVCipherService, never()).encrypt(any(), any());
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingByteArrayAndNullSecretKeyAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.decrypt(NULL_SECRET_KEY, ENCRYPTED_CONTENT_AES));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingByteArrayAndNullSecretKeyAndNonMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.decrypt(NULL_SECRET_KEY, ENCRYPTED_CONTENT_AES));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingByteArrayAndNullEncryptedContentAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final byte[] NULL_ENCRYPTED_CONTENT = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.decrypt(SECRET_KEY_1234567890123456_128_BITS, NULL_ENCRYPTED_CONTENT));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingByteArrayAndNullEncryptedContentAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final byte[] NULL_ENCRYPTED_CONTENT = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () -> aesCipherService.decrypt(SECRET_KEY_1234567890123456_128_BITS, NULL_ENCRYPTED_CONTENT));
  }

  @Test
  void producesNotNullWhenDecryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.decrypt(SECRET_KEY_1234567890123456_128_BITS, ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES);

    // Then
    assertThat(encrypted, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenDecryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.decrypt(SECRET_KEY_1234567890123456_128_BITS, ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES);

    // Then
    assertThat(encrypted.length, is(greaterThan(0)));
  }

  @Test
  void producesTheRightResultWhenDecryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.decrypt(SECRET_KEY_1234567890123456_128_BITS, ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES);

    // Then
    assertThat(encrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void ignoresIVCipherWhenDecryptingByteArrayAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    when(aesNonIVCipherService.decrypt(SECRET_KEY_1234567890123456_128_BITS, ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES);

    // Then
    verify(aesIVCipherService, never()).decrypt(any(), any(), any());
  }

  @Test
  void producesNotNullWhenDecryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(
        aesIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS, ENCRYPTED_CONTENT_AES));

    // Then
    assertThat(encrypted, is(notNullValue()));
  }

  @Test
  void producesNotEmptyWhenDecryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(
        aesIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS, ENCRYPTED_CONTENT_AES));

    // Then
    assertThat(encrypted.length, is(greaterThan(0)));
  }

  @Test
  void producesTheRightResultWhenDecryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(
        aesIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS, ENCRYPTED_CONTENT_AES));

    // Then
    assertThat(encrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void ignoresNonIVTheRightResultWhenDecryptingByteArrayAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(
        aesIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES))
        .thenReturn(CLEAR_CONTENT);

    // When
    final var encrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS, ENCRYPTED_CONTENT_AES));

    // Then
    verify(aesNonIVCipherService, never()).decrypt(any(), any());
  }

  @Test
  void producedOutputFormatWhenEncryptingByteArrayWhichIsValidAsInputForDecryptingWhenIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);
    when(
        aesIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT))
        .thenReturn(ENCRYPTED_CONTENT_AES);

    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encrypted);

    // Then
    verify(aesIVCipherService)
        .decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES);
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingStreamAndNullSecretKeyAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.encrypt(
                NULL_SECRET_KEY,
                clearInputStream,
                encryptedOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingStreamAndNullSecretKeyAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.encrypt(
                NULL_SECRET_KEY,
                clearInputStream,
                encryptedOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingStreamAndNullClearContentInputStreamAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final InputStream NULL_CLEAR_CONTENT_INPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.encrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                NULL_CLEAR_CONTENT_INPUT_STREAM,
                encryptedOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingStreamAndNullClearContentInputStreamAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final InputStream NULL_CLEAR_CONTENT_INPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.encrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                NULL_CLEAR_CONTENT_INPUT_STREAM,
                encryptedOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingStreamAndNullClearContentInputStreamAndMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final InputStream NULL_CLEAR_CONTENT_INPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.encrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                NULL_CLEAR_CONTENT_INPUT_STREAM,
                encryptedOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingStreamAndNullEncryptedOutputStreamAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final OutputStream NULL_ENCRYPTED_OUTPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.encrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                clearInputStream,
                NULL_ENCRYPTED_OUTPUT_STREAM));
  }

  @Test
  void throwsNullPointerExceptionWhenEncryptingStreamAndNullEncryptedOutputStreamAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final OutputStream NULL_ENCRYPTED_OUTPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.encrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                clearInputStream,
                NULL_ENCRYPTED_OUTPUT_STREAM));
  }

  @Test
  void delegatesToNonIVCipherWhenEncryptingStreamAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    verify(aesNonIVCipherService)
        .encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            clearInputStream,
            encryptedOutputStream);
  }

  @Test
  void ignoresIVCipherWhenEncryptingStreamAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    verify(aesIVCipherService, never()).encrypt(any(), any(), any(), any());
  }

  @Test
  void delegatesToIVCipherWhenEncryptingStreamAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    verify(aesIVCipherService)
        .encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            clearInputStream,
            encryptedOutputStream);
  }

  @Test
  void ignoresNonIVCipherWhenEncryptingStreamAndIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    verify(aesNonIVCipherService, never()).encrypt(any(), any(), any());
  }

  @Test
  void prefixesIVAndDelegatesToIVCipherWhenEncryptingStreamAndIVBlockMode() throws IOException {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(randomDataService.generateSecureRandomData(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);

    // When
    aesCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    // Then
    InOrder order = Mockito.inOrder(encryptedOutputStream, aesIVCipherService);
    order.verify(encryptedOutputStream).write(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);
    order.verify(aesIVCipherService)
        .encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            clearInputStream,
            encryptedOutputStream);
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingStreamAndNullSecretKeyAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.decrypt(
                NULL_SECRET_KEY,
                encryptedContentInputStream,
                clearContentOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingStreamAndNullSecretKeyAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final SecretKey NULL_SECRET_KEY = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.decrypt(
                NULL_SECRET_KEY,
                encryptedContentInputStream,
                clearContentOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingStreamAndNullEncryptedContentInputStreamAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final InputStream NULL_ENCRYPTED_CONTENT_INPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.decrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                NULL_ENCRYPTED_CONTENT_INPUT_STREAM,
                clearContentOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingStreamAndNullEncryptedContentInputStreamAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final InputStream NULL_ENCRYPTED_CONTENT_INPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.decrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                NULL_ENCRYPTED_CONTENT_INPUT_STREAM,
                clearContentOutputStream));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingStreamAndNullClearContentOutputStreamAndNonIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    final OutputStream NULL_CLEAR_CONTENT_OUTPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.decrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                encryptedContentInputStream,
                NULL_CLEAR_CONTENT_OUTPUT_STREAM));
  }

  @Test
  void throwsNullPointerExceptionWhenDecryptingStreamAndNullClearContentOutputStreamAndIVMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    final OutputStream NULL_CLEAR_CONTENT_OUTPUT_STREAM = null;

    // Then
    assertThrows(
        NullPointerException.class,
        () ->
            aesCipherService.decrypt(
                SECRET_KEY_1234567890123456_128_BITS,
                encryptedContentInputStream,
                NULL_CLEAR_CONTENT_OUTPUT_STREAM));
  }

  @Test
  void delegatesToNonIVCipherWhenDecryptingStreamAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedContentInputStream,
        clearContentOutputStream);

    // Then
    verify(aesNonIVCipherService)
        .decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            encryptedContentInputStream,
            clearContentOutputStream);
  }

  @Test
  void ignoresIVCipherWhenDecryptingStreamAndNonIVBlockMode() {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            ECB,
            aesNonIVCipherService,
            randomDataService);

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedContentInputStream,
        clearContentOutputStream);

    // Then
    verify(aesIVCipherService, never()).decrypt(any(), any(), any(), any());
  }

  @Test
  void delegatesToIVCipherWhenDecryptingStreamAndIVBlockMode() throws IOException {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(encryptedContentInputStream.readNBytes(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedContentInputStream,
        clearContentOutputStream);

    // Then
    verify(aesIVCipherService)
        .decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            encryptedContentInputStream,
            clearContentOutputStream);
  }

  @Test
  void ignoresNonIVCipherWhenDecryptingStreamAndIVBlockMode() throws IOException {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(encryptedContentInputStream.readNBytes(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedContentInputStream,
        clearContentOutputStream);

    // Then
    verify(aesNonIVCipherService, never()).decrypt(any(), any(), any());
  }

  @Test
  void readsIVAndDelegatesToIVCipherWhenDecryptingStreamAndIVBlockMode() throws IOException {
    // Given
    final SymmetricCipherService aesCipherService =
        new JCAAESCipherService(
            CBC,
            aesIVCipherService,
            randomDataService);

    when(encryptedContentInputStream.readNBytes(anyInt()))
        .thenReturn(INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS);

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedContentInputStream,
        clearContentOutputStream);

    // Then
    verify(aesIVCipherService)
        .decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            encryptedContentInputStream,
            clearContentOutputStream);
  }
}