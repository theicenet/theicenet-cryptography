package com.theicenet.cryptography.acceptancetest.service.asymmetric.rsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.service.asymmetric.rsa.RSASignatureAlgorithm;
import com.theicenet.cryptography.service.asymmetric.rsa.RSASignatureService;
import com.theicenet.cryptography.service.asymmetric.rsa.key.RSAKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class RSASignatureServiceIT {

  final int KEY_LENGTH_2048_BITS = 2048;

  final byte[] CONTENT_256_BITS =
      HexUtil.decodeHex("32aa8dc140ba5165c3ad1d17a1e91bfd234d4ec7a2673b161467551ff1b2410f");

  @Autowired
  RSAKeyService rsaKeyService;

  @Autowired
  RSASignatureService rsaSignatureService;

  @Test
  void signAndVerifyProperly() {
    // Given
    final var SHA1_WITH_RSA = RSASignatureAlgorithm.SHA1withRSA;

    final var rsaKeyPair2048Bits = rsaKeyService.generateKey(KEY_LENGTH_2048_BITS);

    final var signature =
        rsaSignatureService.sign(
            SHA1_WITH_RSA,
            rsaKeyPair2048Bits.getPrivate(),
            CONTENT_256_BITS);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            SHA1_WITH_RSA,
            rsaKeyPair2048Bits.getPublic(),
            CONTENT_256_BITS,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }
}
