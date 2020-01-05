package com.theicenet.cryptography.acceptancetest.cipher.symmetric.aes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVBasedCipherService;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AESCipherServiceIT {

  final String AES = "AES";

  final byte[] CLEAR_CONTENT =
      "Content to encrypt with AES and different options for block cipher mode of operation"
          .getBytes(StandardCharsets.UTF_8);

  final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  final byte[] INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS =
      "KLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  static final byte[] ENCRYPTED_CONTENT_AES_CFB =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc9126d4c171c5e"
              + "fc1c3c7137e9d2fb2f711897b3261d0f760243583"
              + "5a693ab44f52b0e51c889504655b6a88c64c446b6"
              + "669dfc61c082e932ec53767b3de363beb10fa3ceb"
              + "2ed8");

  @Autowired
  @Qualifier("AESCipher")
  SymmetricIVBasedCipherService aesCipherService;

  @Test
  void producesTheRightEncryptedResultWhenEncryptingByteArray() {
    // When
    final var encrypted =
        aesCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_CFB)));
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
        encryptedOutputStream);

    // Then
    assertThat(encryptedOutputStream.toByteArray(), is(equalTo(ENCRYPTED_CONTENT_AES_CFB)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingByteArray() {
    // When
    final var decrypted =
        aesCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CFB);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingStream() {
    // Given
    final var encryptedInputStream = new ByteArrayInputStream(ENCRYPTED_CONTENT_AES_CFB);
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(equalTo(CLEAR_CONTENT)));
  }
}