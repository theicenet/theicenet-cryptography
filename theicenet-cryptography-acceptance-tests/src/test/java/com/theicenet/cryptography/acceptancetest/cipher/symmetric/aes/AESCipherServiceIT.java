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
package com.theicenet.cryptography.acceptancetest.cipher.symmetric.aes;

import static com.theicenet.cryptography.util.ByteArraysUtil.concat;
import static com.theicenet.cryptography.util.ByteArraysUtil.split;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.cipher.symmetric.SymmetricAEADCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVCipherService;
import com.theicenet.cryptography.test.support.HexUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Juan Fidalgo
 */
@SpringBootTest
class AESCipherServiceIT {

  final String AES = "AES";

  final int IV_SIZE_16_BYTES = 16;

  final byte[] CLEAR_CONTENT =
      "Content to encrypt with AES and different options for block cipher mode of operation"
          .getBytes(StandardCharsets.UTF_8);

  final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  final byte[] INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS =
      "KLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] ENCRYPTED_CONTENT_AES_ECB =
      HexUtil.decodeHex(
          "1f28432db0cb9a41a18068300e9731fc816b36e9b78d803"
              + "e8ad1d7828ab8ceef25722793b8c8e0b3a4c72f12"
              + "ded24ea264d2c988f17d8d44c249b3f8e588b41a7"
              + "ab826fc440227e99ae6e1df2d50b4b00fce059bc3"
              + "2c93e9fd7c5938327e38ab");

  final byte[] ENCRYPTED_CONTENT_AES_CBC =
      HexUtil.decodeHex(
          "e9ace3b5980b905b3c5823555dbea50b69d0b3129f3aa25"
              + "40255b35dc5d46128a83ae6989e4d94ed83d6ffcb"
              + "4210ddd9686719807ed8537e6040d3cb332a63dfe"
              + "642db91b1e39bad80fa8a86329b04ee8ee57305ff"
              + "62e7daf001897f7c4a1e5a");

  final byte[] ENCRYPTED_CONTENT_AES_CFB =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc9126d4c171c5efc1c3c"
              + "7137e9d2fb2f711897b3261d0f7602435835a693a"
              + "b44f52b0e51c889504655b6a88c64c446b6669dfc"
              + "61c082e932ec53767b3de363beb10fa3ceb2ed8");

  final byte[] ENCRYPTED_CONTENT_AES_OFB =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc91263746a29bdf2e031"
              + "c65d44d000366eff30193861a14b73867329da374"
              + "a511cc52dbfa0fc116f47423ed37694ceb016afd3"
              + "b208a31e1aa4a7eb99b4f7e57966ec1376588d1");

  final byte[] ENCRYPTED_CONTENT_AES_CTR =
      HexUtil.decodeHex(
          "813d91455835f9650de0506a0cbc9126da73e6e016a787a"
              + "39e6f0bd8914874f6af0f2fca309465217d86aa55"
              + "d9a1689666ce4189cb6194e1ac20e0ea5e2e60ec7"
              + "0b0f31255a4dc6cf304edb4192d28c725751474");

  static final byte[] ASSOCIATED_DATA_1 = "Associated data one.".getBytes(StandardCharsets.UTF_8);
  static final byte[] ASSOCIATED_DATA_2 = "Associated data two.".getBytes(StandardCharsets.UTF_8);

  static final byte[] AUTHENTICATION_TAG_NO_AD_GCM =
      HexUtil.decodeHex("ed7f1709863b083e6a7346320f8a5ca9");

  static final byte[] AUTHENTICATION_TAG_WITH_AD_GCM =
      HexUtil.decodeHex("ded15a2d500fcd26a9501be9cef83a17");

  static final byte[] ENCRYPTED_CONTENT_AES_GCM =
      HexUtil.decodeHex(
          "868b0a81b19cc4392191909c349d722395c713a4d3ed3"
              + "5f88b323e5257182434d9c3689057800c25e15b"
              + "143e73ba69fccdc25902183db754e0417928895"
              + "4a78d6a21eb25ca6b5f33054ce19671b7150c9c"
              + "0ea1ea");

  @Autowired
  @Qualifier("AESNonIVCipher_ECB")
  SymmetricNonIVCipherService aesECBNonIVCipherService;

  @Autowired
  @Qualifier("AESIVCipher_CBC")
  SymmetricIVCipherService aesCBCIVCipherService;

  @Autowired
  @Qualifier("AESIVCipher_CFB")
  SymmetricIVCipherService aesCFBIVCipherService;

  @Autowired
  @Qualifier("AESIVCipher_OFB")
  SymmetricIVCipherService aesOFBIVCipherService;

  @Autowired
  @Qualifier("AESIVCipher_CTR")
  SymmetricIVCipherService aesCTRIVCipherService;

  @Autowired
  @Qualifier("AESIVCipher_GCM")
  SymmetricIVCipherService aesGCMIVCipherService;

  @Autowired
  @Qualifier("AESAEADCipher_GCM")
  SymmetricAEADCipherService aesGCMAEADCipherService;

  @Autowired
  @Qualifier("AESCipher_ECB")
  SymmetricCipherService aesECBCipherService;

  @Autowired
  @Qualifier("AESCipher_CBC")
  SymmetricCipherService aesCBCCipherService;

  @Autowired
  @Qualifier("AESCipher_CFB")
  SymmetricCipherService aesCFBCipherService;

  @Autowired
  @Qualifier("AESCipher_OFB")
  SymmetricCipherService aesOFBCipherService;

  @Autowired
  @Qualifier("AESCipher_CTR")
  SymmetricCipherService aesCTRCipherService;

  @Autowired
  @Qualifier("AESCipher_GCM")
  SymmetricCipherService aesGCMCipherService;

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithECB() {
    // When
    final var encrypted =
        aesECBNonIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_ECB)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithCBC() {
    // When
    final var encrypted =
        aesCBCIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_CBC)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithCFB() {
    // When
    final var encrypted =
        aesCFBIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_CFB)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithOFB() {
    // When
    final var encrypted =
        aesOFBIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_OFB)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithCTR() {
    // When
    final var encrypted =
        aesCTRIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(encrypted, is(equalTo(ENCRYPTED_CONTENT_AES_CTR)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithGCM() {
    // When
    final var encrypted =
        aesGCMIVCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(
        encrypted,
        is(equalTo(concat(ENCRYPTED_CONTENT_AES_GCM, AUTHENTICATION_TAG_NO_AD_GCM))));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithGCMAndAssociatedData() {
    // When
    final var encrypted =
        aesGCMAEADCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            CLEAR_CONTENT,
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(
        encrypted,
        is(equalTo(concat(ENCRYPTED_CONTENT_AES_GCM, AUTHENTICATION_TAG_WITH_AD_GCM))));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithECBAndEasyToUseAESCipher() {
    // When
    final var encrypted =
        aesECBCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    assertThat(
        encrypted,
        is(equalTo(ENCRYPTED_CONTENT_AES_ECB)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithCBCAndEasyToUseAESCipher() {
    // When
    final var ivAndEncrypted =
        aesCBCCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    final byte[] decryptedWithIVCipher =
        decryptWithIVCipher(
            aesCBCIVCipherService,
            SECRET_KEY_1234567890123456_128_BITS,
            ivAndEncrypted);

    assertThat(
        decryptedWithIVCipher,
        is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithCFBAndEasyToUseAESCipher() {
    // When
    final var ivAndEncrypted =
        aesCFBCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    final byte[] decryptedWithIVCipher =
        decryptWithIVCipher(
            aesCFBIVCipherService,
            SECRET_KEY_1234567890123456_128_BITS,
            ivAndEncrypted);

    assertThat(
        decryptedWithIVCipher,
        is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithOFBAndEasyToUseAESCipher() {
    // When
    final var ivAndEncrypted =
        aesOFBCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    final byte[] decryptedWithIVCipher =
        decryptWithIVCipher(
            aesOFBIVCipherService,
            SECRET_KEY_1234567890123456_128_BITS,
            ivAndEncrypted);

    assertThat(
        decryptedWithIVCipher,
        is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithCTRAndEasyToUseAESCipher() {
    // When
    final var ivAndEncrypted =
        aesCTRCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    final byte[] decryptedWithIVCipher =
        decryptWithIVCipher(
            aesCTRIVCipherService,
            SECRET_KEY_1234567890123456_128_BITS,
            ivAndEncrypted);

    assertThat(
        decryptedWithIVCipher,
        is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightEncryptedResultWhenEncryptingWithGCMAndEasyToUseAESCipher() {
    // When
    final var ivAndEncrypted =
        aesGCMCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // Then
    final byte[] decryptedWithIVCipher =
        decryptWithIVCipher(
            aesGCMIVCipherService,
            SECRET_KEY_1234567890123456_128_BITS,
            ivAndEncrypted);

    assertThat(
        decryptedWithIVCipher,
        is(equalTo(CLEAR_CONTENT)));
  }

  byte[] decryptWithIVCipher(
      SymmetricIVCipherService ivCipherService,
      SecretKey secretKey,
      byte[] ivAndEncrypted) {

    final byte[][] ivAndEncryptedSplit = split(ivAndEncrypted, IV_SIZE_16_BYTES);
    final byte[] iv = ivAndEncryptedSplit[0];
    final byte[] encrypted = ivAndEncryptedSplit[1];

    return
        ivCipherService.decrypt(
            secretKey,
            iv,
            encrypted);
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithECB() {
    // When
    final var decrypted =
        aesECBNonIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithCBC() {
    // When
    final var decrypted =
        aesCBCIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CBC);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithCFB() {
    // When
    final var decrypted =
        aesCFBIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CFB);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithOFB() {
    // When
    final var decrypted =
        aesOFBIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_OFB);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithCTR() {
    // When
    final var decrypted =
        aesCTRIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            ENCRYPTED_CONTENT_AES_CTR);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithGCM() {
    // When
    final var decrypted =
        aesGCMIVCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            concat(ENCRYPTED_CONTENT_AES_GCM, AUTHENTICATION_TAG_NO_AD_GCM));

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithGCMAndAssociatedData() {
    // When
    final var decrypted =
        aesGCMAEADCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
            concat(ENCRYPTED_CONTENT_AES_GCM, AUTHENTICATION_TAG_WITH_AD_GCM),
            ASSOCIATED_DATA_1,
            ASSOCIATED_DATA_2);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithECBAndEasyToUseAESCipher() {
    // When
    final var decrypted =
        aesECBCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            ENCRYPTED_CONTENT_AES_ECB);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithECBAndEasyToUseCBCCipher() {
    // When
    final var decrypted =
        aesCBCCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                ENCRYPTED_CONTENT_AES_CBC));

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithECBAndEasyToUseCFBCipher() {
    // When
    final var decrypted =
        aesCFBCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                ENCRYPTED_CONTENT_AES_CFB));

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithECBAndEasyToUseOFBCipher() {
    // When
    final var decrypted =
        aesOFBCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                ENCRYPTED_CONTENT_AES_OFB));

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithECBAndEasyToUseCTRCipher() {
    // When
    final var decrypted =
        aesCTRCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                ENCRYPTED_CONTENT_AES_CTR));

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producesTheRightDecryptedResultWhenDecryptingWithGCMAndEasyToUseCipher() {
    // When
    final var decrypted =
        aesGCMCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            concat(
                INITIALIZATION_VECTOR_KLMNOPQRSTUVWXYZ_128_BITS,
                ENCRYPTED_CONTENT_AES_GCM,
                AUTHENTICATION_TAG_NO_AD_GCM));

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producedOutputFormatWhenEncryptingByteArrayWhichIsValidAsInputForDecryptingWhenNonIVBlockModeAndEasyAESCipher() {
    // Given
    final var encrypted =
        aesECBCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // When
    final byte[] decrypted =
        aesECBCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            encrypted);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producedOutputFormatWhenEncryptingByteArrayWhichIsValidAsInputForDecryptingWhenIVBlockModeAndEasyAESCipher() {
    // Given
    final var encrypted =
        aesCBCCipherService.encrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            CLEAR_CONTENT);

    // When
    final byte[] decrypted =
        aesCBCCipherService.decrypt(
            SECRET_KEY_1234567890123456_128_BITS,
            encrypted);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producedOutputFormatWhenEncryptingStreamWhichIsValidAsInputForDecryptingWhenNonIVBlockModeAndEasyAESCipher() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    aesECBCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    final var encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray());
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesECBCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void producedOutputFormatWhenEncryptingStreamWhichIsValidAsInputForDecryptingWhenIVBlockModeAndEasyAESCipher() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CLEAR_CONTENT);
    final var encryptedOutputStream = new ByteArrayOutputStream();

    aesCBCCipherService.encrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        clearInputStream,
        encryptedOutputStream);

    final var encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray());
    final var clearOutputStream = new ByteArrayOutputStream();

    // When
    aesCBCCipherService.decrypt(
        SECRET_KEY_1234567890123456_128_BITS,
        encryptedInputStream,
        clearOutputStream);

    // Then
    assertThat(clearOutputStream.toByteArray(), is(equalTo(CLEAR_CONTENT)));
  }
}