package com.theicenet.cryptography.acceptancetest.service.asymmetric.dsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.service.asymmetric.dsa.DSASignatureAlgorithm;
import com.theicenet.cryptography.service.asymmetric.dsa.DSASignatureService;
import com.theicenet.cryptography.service.asymmetric.dsa.key.DSAKeyService;
import com.theicenet.cryptography.service.asymmetric.rsa.RSASignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class DSASignatureServiceIT {

  final int KEY_LENGTH_2048_BITS = 2048;

  final byte[] CONTENT =
      "Content to be signed to test correctness of the DSA sign implementation."
          .getBytes(StandardCharsets.UTF_8);

  @Autowired
  DSAKeyService dsaKeyService;

  @Autowired
  DSASignatureService dsaSignatureService;

  @Test
  void signsAndVerifiesProperly() {
    // Given
    final var SHA1_WITH_DSA = DSASignatureAlgorithm.SHA1withDSA;

    final var dsaKeyPair2048Bits = dsaKeyService.generateKey(KEY_LENGTH_2048_BITS);

    final var signature =
        dsaSignatureService.sign(
            SHA1_WITH_DSA,
            dsaKeyPair2048Bits.getPrivate(),
            CONTENT);

    // When
    final var verifyingResult =
        dsaSignatureService.verify(
            SHA1_WITH_DSA,
            dsaKeyPair2048Bits.getPublic(),
            CONTENT,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }
}
