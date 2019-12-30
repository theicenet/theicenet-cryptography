package com.theicenet.cryptography.acceptancetest.service.asymmetric.rsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.service.asymmetric.rsa.RSACryptographyService;
import com.theicenet.cryptography.service.asymmetric.rsa.RSAPadding;
import com.theicenet.cryptography.service.asymmetric.rsa.key.RSAKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class RSACryptographyServiceIT {

  final int KEY_LENGTH_2048_BITS = 2048;

  final byte[] CONTENT_256_BITS =
      HexUtil.decodeHex("32aa8dc140ba5165c3ad1d17a1e91bfd234d4ec7a2673b161467551ff1b2410f");

  @Autowired
  RSAKeyService rsaKeyService;

  @Autowired
  RSACryptographyService rsaCryptographyService;

  @Test
  void encryptAndDecryptProperly() {
    // Given
    final var PADDING_OAEP_WITH_SHA1_AND_MGF1 = RSAPadding.OAEPWithSHA1AndMGF1Padding;

    final var rsaKeyPair2048Bits = rsaKeyService.generateKey(KEY_LENGTH_2048_BITS);

    final var encrypted =
        rsaCryptographyService.encrypt(
            PADDING_OAEP_WITH_SHA1_AND_MGF1,
            rsaKeyPair2048Bits.getPublic(),
            CONTENT_256_BITS);

    // When
    final var decrypted =
        rsaCryptographyService.decrypt(
            PADDING_OAEP_WITH_SHA1_AND_MGF1,
            rsaKeyPair2048Bits.getPrivate(),
            encrypted);

    // Then
    assertThat(decrypted, is(equalTo(CONTENT_256_BITS)));
  }
}
