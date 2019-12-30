package com.theicenet.cryptography.service.asymmetric.rsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.service.asymmetric.rsa.key.JCARSAKeyService;
import com.theicenet.cryptography.service.asymmetric.rsa.key.RSAKeyService;
import com.theicenet.cryptography.test.util.HexUtil;
import java.security.KeyPair;
import java.security.SecureRandom;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class JCARSASignatureServiceTest {

  final int KEY_LENGTH_2048_BITS = 2048;

  final byte[] CONTENT_256_BITS =
      HexUtil.decodeHex("32aa8dc140ba5165c3ad1d17a1e91bfd234d4ec7a2673b161467551ff1b2410f");

  final byte[] DIFFERENT_CONTENT_256_BITS =
      HexUtil.decodeHex("a6f9553e1ff2d0430acf5542a6b83eacc32db589b7494643c1fd66a664b9d1e3");

  final KeyPair RSA_KEY_PAIR_2048_BITS;

  RSASignatureService rsaSignatureService;

  public JCARSASignatureServiceTest() {
    RSAKeyService rsaKeyService = new JCARSAKeyService(new SecureRandom());
    RSA_KEY_PAIR_2048_BITS = rsaKeyService.generateKey(KEY_LENGTH_2048_BITS);

    rsaSignatureService = new JCARSASignatureService();
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesNotNullWhenSigning(RSASignatureAlgorithm algorithm) {
    // When
    final var signature =
        rsaSignatureService.sign(
            algorithm,
            RSA_KEY_PAIR_2048_BITS.getPrivate(),
            CONTENT_256_BITS);

    // Then
    assertThat(signature, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesSizeOfSignatureEqualsToKeyLengthWhenSigning(RSASignatureAlgorithm algorithm) {
    // When
    final var signature =
        rsaSignatureService.sign(
            algorithm,
            RSA_KEY_PAIR_2048_BITS.getPrivate(),
            CONTENT_256_BITS);

    // Then
    assertThat(signature.length, is(equalTo(KEY_LENGTH_2048_BITS / 8)));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesSignatureDifferentToClearContentWhenSigning(RSASignatureAlgorithm algorithm) {
    // When
    final var signature =
        rsaSignatureService.sign(
            algorithm,
            RSA_KEY_PAIR_2048_BITS.getPrivate(),
            CONTENT_256_BITS);

    // Then
    assertThat(signature, is(not(equalTo(CONTENT_256_BITS))));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void verifiesSignatureTrueWhenVerifyingTheRightSignature(RSASignatureAlgorithm algorithm) {
    // Given
    final var signature =
        rsaSignatureService.sign(
            algorithm,
            RSA_KEY_PAIR_2048_BITS.getPrivate(),
            CONTENT_256_BITS);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            algorithm,
            RSA_KEY_PAIR_2048_BITS.getPublic(),
            CONTENT_256_BITS,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void verifiesSignatureFalseWhenVerifyingTheWrongSignature(RSASignatureAlgorithm algorithm) {
    // Given
    final var signature =
        rsaSignatureService.sign(
            algorithm,
            RSA_KEY_PAIR_2048_BITS.getPrivate(),
            CONTENT_256_BITS);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            algorithm,
            RSA_KEY_PAIR_2048_BITS.getPublic(),
            DIFFERENT_CONTENT_256_BITS,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(false)));
  }
}