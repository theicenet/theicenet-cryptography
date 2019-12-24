package com.theicenet.cryptography.acceptancetest.service.symmetric.aes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.service.symmetric.aes.AESCryptographyService;
import com.theicenet.cryptography.service.symmetric.aes.BlockCipherModeOfOperation;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class JCAAESCryptographyServiceIT {

  final String AES = "AES";
  final BlockCipherModeOfOperation CTR = BlockCipherModeOfOperation.CTR;

  final byte[] CLEAR_CONTENT =
      "Content to encrypt with AES and different options for block cipher mode of operation"
          .getBytes(StandardCharsets.UTF_8);

  final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  final byte[] INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS =
      "KLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] ENCRYPTED_CONTENT_AES_CTR =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc9126da73e6"
              + "e016a787a39e6f0bd8914874f6af0f2fca3094"
              + "65217d86aa55d9a1689666ce4189cb6194e1ac"
              + "20e0ea5e2e60ec70b0f31255a4dc6cf304edb41"
              + "92d28c725751474");

  @Autowired
  AESCryptographyService aesCryptographyService;

  @Test
  void producesTheRightEncryptedResultWhenEncrypting() {
    // When
    final var encrypted =
        aesCryptographyService.encrypt(
            CTR,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_CTR)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecrypting() {
    // When
    final var decrypted =
        aesCryptographyService.decrypt(
            CTR,
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CTR);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }
}