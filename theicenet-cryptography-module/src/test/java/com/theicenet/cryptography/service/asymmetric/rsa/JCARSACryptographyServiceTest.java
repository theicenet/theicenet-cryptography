package com.theicenet.cryptography.service.asymmetric.rsa;

import com.theicenet.cryptography.service.asymmetric.rsa.key.JCARSAKeyService;
import com.theicenet.cryptography.service.asymmetric.rsa.key.RSAKeyService;
import com.theicenet.cryptography.test.util.HexUtil;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.security.SecureRandom;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

class JCARSACryptographyServiceTest {

    final int KEY_LENGTH_2048_BITS = 2048;

    final byte[] CLEAR_CONTENT_512_BITS =
            HexUtil.decodeHex(
                    "dbb3ed4ebdea702402d592eb2d2289ec6f8a1eb92057d16a0da36c60bb5f2877739ac5996a" +
                            "2d2f7d4283d3d6fd89360701c6019c9928b47d33583c001271f382");

    final KeyPair RSA_KEY_PAIR_2048_BITS;

    RSACryptographyService rsaCryptographyService;

    public JCARSACryptographyServiceTest() {
        RSAKeyService rsaKeyService = new JCARSAKeyService(new SecureRandom());
        RSA_KEY_PAIR_2048_BITS = rsaKeyService.generateKey(KEY_LENGTH_2048_BITS);

        rsaCryptographyService = new JCARSACryptographyService();
    }

    @ParameterizedTest
    @EnumSource(Padding.class)
    void producesNotNullWhenEncrypting(Padding padding) {
        // When
        final var encrypted =
                rsaCryptographyService.encrypt(
                        padding,
                        RSA_KEY_PAIR_2048_BITS.getPublic(),
                        CLEAR_CONTENT_512_BITS);

        // Then
        assertThat(encrypted, is(notNullValue()));
    }

    @ParameterizedTest
    @EnumSource(Padding.class)
    void producesSizeOfEncryptedEqualsToKeyLengthWhenEncrypting(Padding padding) {
        // When
        final var encrypted =
                rsaCryptographyService.encrypt(
                        padding,
                        RSA_KEY_PAIR_2048_BITS.getPublic(),
                        CLEAR_CONTENT_512_BITS);

        // Then
        assertThat(encrypted.length, is(equalTo(KEY_LENGTH_2048_BITS / 8)));
    }

    @ParameterizedTest
    @EnumSource(Padding.class)
    void producesEncryptedDifferentToClearContentWhenEncrypting(Padding padding) {
        // When
        final var encrypted =
                rsaCryptographyService.encrypt(
                        padding,
                        RSA_KEY_PAIR_2048_BITS.getPublic(),
                        CLEAR_CONTENT_512_BITS);

        // Then
        assertThat(encrypted, is(not(equalTo(CLEAR_CONTENT_512_BITS))));
    }

    @ParameterizedTest
    @EnumSource(Padding.class)
    void producesTheClearContentWhenDecrypting(Padding padding) {
        // Given
        final var encrypted =
                rsaCryptographyService.encrypt(
                        padding,
                        RSA_KEY_PAIR_2048_BITS.getPublic(),
                        CLEAR_CONTENT_512_BITS);

        // When
        final var decrypted =
                rsaCryptographyService.decrypt(
                        padding,
                        RSA_KEY_PAIR_2048_BITS.getPrivate(),
                        encrypted);

        // Then
        assertThat(decrypted, is(equalTo(CLEAR_CONTENT_512_BITS)));
    }
}