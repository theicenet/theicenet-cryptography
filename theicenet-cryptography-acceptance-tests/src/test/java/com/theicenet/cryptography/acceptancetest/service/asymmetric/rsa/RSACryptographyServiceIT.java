package com.theicenet.cryptography.acceptancetest.service.asymmetric.rsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.service.asymmetric.rsa.RSACryptographyService;
import com.theicenet.cryptography.service.asymmetric.rsa.key.RSAKeyService;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class RSACryptographyServiceIT {

  final int KEY_LENGTH_2048_BITS = 2048;

  final byte[] CLEAR_CONTENT =
      "Content to be encrypted to test correctness of the RSA encrypt/decrypt implementation."
          .getBytes(StandardCharsets.UTF_8);

  @Autowired
  RSAKeyService rsaKeyService;

  @Autowired
  RSACryptographyService rsaCryptographyService;

  @Test
  void encryptsAndDecryptsProperly() {
    // Given
    final var rsaKeyPair2048Bits = rsaKeyService.generateKey(KEY_LENGTH_2048_BITS);

    final var encrypted =
        rsaCryptographyService.encrypt(
            rsaKeyPair2048Bits.getPublic(),
            CLEAR_CONTENT);

    // When
    final var decrypted =
        rsaCryptographyService.decrypt(
            rsaKeyPair2048Bits.getPrivate(),
            encrypted);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }
}
