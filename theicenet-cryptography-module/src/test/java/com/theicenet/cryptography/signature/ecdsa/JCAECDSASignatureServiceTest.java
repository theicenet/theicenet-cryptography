package com.theicenet.cryptography.signature.ecdsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.CombinableMatcher.both;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThanOrEqualTo;
import static org.hamcrest.number.OrderingComparison.lessThanOrEqualTo;

import com.theicenet.cryptography.signature.SignatureService;
import com.theicenet.cryptography.test.util.HexUtil;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class JCAECDSASignatureServiceTest {
  final String ECDSA = "ECDSA";

  final byte[] CONTENT =
      "Content to be signed to test correctness of the ECDSA sign implementation."
          .getBytes(StandardCharsets.UTF_8);

  final byte[] DIFFERENT_CONTENT =
      "Totally different content to test that verify detects properly when signature is not correct."
          .getBytes(StandardCharsets.UTF_8);

  final byte[] ECDSA_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY =
      HexUtil.decodeHex(
          "305a301406072a8648ce3d020106092b240303020801010703420004276492e8990f82e5b"
              + "31d4931a35591756eb24db1534fae485e0e62a2a2188c6da2896928c35032e1b664"
              + "125225559865b03bf436fe1ccf368443bb7397dfc39e");

  final byte[] ECDSA_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY =
      HexUtil.decodeHex(
          "308188020100301406072a8648ce3d020106092b2403030208010107046d306b0201010420"
              + "824fb7361bcbdeea14011309fc016cac8180ce62fffa8e7e677646ac961ccfb4a144"
              + "03420004276492e8990f82e5b31d4931a35591756eb24db1534fae485e0e62a2a218"
              + "8c6da2896928c35032e1b664125225559865b03bf436fe1ccf368443bb7397dfc39e");

  final PublicKey ECDSA_PUBLIC_KEY_BRAINPOOLP256R1;
  final PrivateKey ECDSA_PRIVATE_KEY_BRAINPOOLP256R1;

  final byte[] SIGNATURE_SHA1_WITH_ECDSA =
      HexUtil.decodeHex(
          "304402206a2d12c6d68a10d93226fd858217077ce9eaa3c0a46ca6f8d89d411f5b69d865022060"
              + "865ee94b85228f4a19e492817d633717bb9a8fb9b78ecd67365918c1050848");

  final byte[] SIGNATURE_SHA224_WITH_ECDSA =
      HexUtil.decodeHex(
          "30440220459227e4286b0d68a6e93e0c0cb91b660e7e88c8397860c63607640fd0e5273502204b"
              + "4bf0d0c3a7b7a1a1cd47dc2b8367ac4ecad8a59f5ed3362d716a8058b7bc77");

  final byte[] SIGNATURE_SHA256_WITH_ECDSA =
      HexUtil.decodeHex(
          "304402202be4286aa2daf28ef992e52f360888987df981da2495553c49510358d84b6198022078f"
              + "bc3d6a0037c682454e908f463997a094222687af9232204f05d0001951291");

  JCAECDSASignatureServiceTest() throws Exception {
    // Bouncy Castle is required for ECDSA key factory
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();

    final var keyFactory = KeyFactory.getInstance(ECDSA);

    final var x509EncodedKeySpec = new X509EncodedKeySpec(
        ECDSA_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY);
    ECDSA_PUBLIC_KEY_BRAINPOOLP256R1 = keyFactory.generatePublic(x509EncodedKeySpec);

    final var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
        ECDSA_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY);
    ECDSA_PRIVATE_KEY_BRAINPOOLP256R1 = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producesNotNullWhenSigningByteArray(ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);

    // When
    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            CONTENT);

    // Then
    assertThat(signature, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producesNotNullWhenSigningByteStream(ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            contentInputStream);

    // Then
    assertThat(signature, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producesRightSizeWhenSigningByteArray(ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);

    // When
    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            CONTENT);

    // Then
    assertThat( // For a curve between 160 and 512 bits key the signature size should be between 68 and 72 bytes
        signature.length,
        is(both(greaterThanOrEqualTo(68)).and(lessThanOrEqualTo(72))));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producesRightSizeWhenSigningStream(ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            contentInputStream);

    // Then
    assertThat( // For a curve between 160 and 512 bits key the signature size should be between 68 and 72 bytes
        signature.length,
        is(both(greaterThanOrEqualTo(68)).and(lessThanOrEqualTo(72))));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producesSignatureDifferentToClearContentWhenSigningByteArray(ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);

    // When
    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            CONTENT);

    // Then
    assertThat(signature, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producesSignatureDifferentToClearContentWhenSigningStream(ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            contentInputStream);

    // Then
    assertThat(signature, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producedSignatureVerifiesToTrueWhenVerifyingByteArrayAndSignatureCorrespondsWithContent(
      ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);

    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            CONTENT);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            CONTENT,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void producedSignatureVerifiesToTrueWhenVerifyingStreamAndSignatureCorrespondsWithContent(
      ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);

    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            CONTENT);

    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            contentInputStream,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void signatureVerifiesToFalseWhenVerifyingByteArrayAndSignatureDoesNotCorrespondsWithContent(
      ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);

    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            CONTENT);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            DIFFERENT_CONTENT,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(false)));
  }

  @ParameterizedTest
  @EnumSource(ECDSASignatureAlgorithm.class)
  void signatureVerifiesToFalseWhenVerifyingStreamAndSignatureDoesNotCorrespondsWithContent(
      ECDSASignatureAlgorithm algorithm) {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(algorithm);

    final var signature =
        ecdsaSignatureService.sign(
            ECDSA_PRIVATE_KEY_BRAINPOOLP256R1,
            CONTENT);

    final var differentContentInputStream = new ByteArrayInputStream(DIFFERENT_CONTENT);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            differentContentInputStream,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(false)));
  }

  @Test
  void verifiesProperlyWhenVerifyingByteArrayWithSha1WithECDSA() {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(ECDSASignatureAlgorithm.SHA1withECDSA);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            CONTENT,
            SIGNATURE_SHA1_WITH_ECDSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingStreamWithSha1WithECDSA() {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(ECDSASignatureAlgorithm.SHA1withECDSA);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            contentInputStream,
            SIGNATURE_SHA1_WITH_ECDSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingByteArrayWithSha224WithECDSA() {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(ECDSASignatureAlgorithm.SHA224withECDSA);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            CONTENT,
            SIGNATURE_SHA224_WITH_ECDSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingStreamWithSha224WithECDSA() {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(ECDSASignatureAlgorithm.SHA224withECDSA);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            contentInputStream,
            SIGNATURE_SHA224_WITH_ECDSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingByteArrayWithSha256WithECDSA() {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(ECDSASignatureAlgorithm.SHA256withECDSA);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            CONTENT,
            SIGNATURE_SHA256_WITH_ECDSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingStreamWithSha256WithECDSA() {
    // Given
    SignatureService ecdsaSignatureService = new JCAECDSASignatureService(ECDSASignatureAlgorithm.SHA256withECDSA);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var verifyingResult =
        ecdsaSignatureService.verify(
            ECDSA_PUBLIC_KEY_BRAINPOOLP256R1,
            contentInputStream,
            SIGNATURE_SHA256_WITH_ECDSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }
}