package com.theicenet.cryptography.cipher.symmetric.aes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;

import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherService;
import com.theicenet.cryptography.test.util.HexUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JCAAESECBCipherServiceTest {
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

  SymmetricCipherService aesCipherService;

  @BeforeEach
  void setUp() {
    aesCipherService = new JCAAESECBCipherService();
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
}