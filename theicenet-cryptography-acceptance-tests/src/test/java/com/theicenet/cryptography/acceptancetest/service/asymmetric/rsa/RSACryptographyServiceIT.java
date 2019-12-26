package com.theicenet.cryptography.acceptancetest.service.asymmetric.rsa;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.service.asymmetric.rsa.Padding;
import com.theicenet.cryptography.service.asymmetric.rsa.RSACryptographyService;
import com.theicenet.cryptography.service.asymmetric.rsa.key.RSAKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

@SpringBootTest
public class RSACryptographyServiceIT {

    final byte[] CLEAR_CONTENT_512_BITS =
            HexUtil.decodeHex(
                    "dbb3ed4ebdea702402d592eb2d2289ec6f8a1eb92057d16a0da36c60bb5f2877739ac5996a" +
                            "2d2f7d4283d3d6fd89360701c6019c9928b47d33583c001271f382");

    @Autowired
    RSAKeyService rsaKeyService;

    @Autowired
    RSACryptographyService rsaCryptographyService;

    @Test
    void producesTheClearContentWhenDecrypting() {
        // Given
        final var PADDING_OAEP_WITH_SHA1_AND_MGF1 = Padding.OAEPWithSHA1AndMGF1Padding;

        final var rsaKeyPair2048Bits = rsaKeyService.generateKey(2048);

        final var encrypted =
                rsaCryptographyService.encrypt(
                        PADDING_OAEP_WITH_SHA1_AND_MGF1,
                        rsaKeyPair2048Bits.getPublic(),
                        CLEAR_CONTENT_512_BITS);

        // When
        final var decrypted =
                rsaCryptographyService.decrypt(
                        PADDING_OAEP_WITH_SHA1_AND_MGF1,
                        rsaKeyPair2048Bits.getPrivate(),
                        encrypted);

        // Then
        assertThat(decrypted, is(equalTo(CLEAR_CONTENT_512_BITS)));
    }
}
