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
class AESCryptographyServiceIT {

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
  AESCryptographyService aesCryptographyService;

  @Test
  void producesTheRightEncryptedResultWhenEncrypting() {
    // When
    final var encrypted =
        aesCryptographyService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_CFB)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecrypting() {
    // When
    final var decrypted =
        aesCryptographyService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CFB);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }
}