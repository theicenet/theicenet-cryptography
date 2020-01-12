package com.theicenet.cryptography.digest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

class JCADigestServiceTest {

  final byte[] CONTENT =
      "Content to digest with different algorithm to check the digesting implementation is correct"
          .getBytes(StandardCharsets.UTF_8);

  DigestService digestService;

  @ParameterizedTest
  @EnumSource(DigestAlgorithm.class)
  void producesNotNullWhenDigestingByteArray(DigestAlgorithm algorithm) {
    // Given
    digestService = new JCADigestService(algorithm);

    // When
    final var hash = digestService.digest(CONTENT);

    // Then
    assertThat(hash, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(DigestAlgorithm.class)
  void producesNotNullWhenDigestingStream(DigestAlgorithm algorithm) {
    // Given
    digestService = new JCADigestService(algorithm);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var hash = digestService.digest(contentInputStream);

    // Then
    assertThat(hash, is(notNullValue()));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithDigestAlgorithmAndItsHashSizeInBits")
  void producesTheRightHashSizeWhenDigestingByteArray(DigestAlgorithm algorithm, Integer hashSizeInBits) {
    // Given
    digestService = new JCADigestService(algorithm);

    // When
    final var hash = digestService.digest(CONTENT);

    // Then
    assertThat(hash.length * 8, is(equalTo(hashSizeInBits)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithDigestAlgorithmAndItsHashSizeInBits")
  void producesTheRightHashSizeWhenDigestingStream(DigestAlgorithm algorithm, Integer hashSizeInBits) {
    // Given
    digestService = new JCADigestService(algorithm);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var hash = digestService.digest(contentInputStream);

    // Then
    assertThat(hash.length * 8, is(equalTo(hashSizeInBits)));
  }


  static Stream<Arguments> argumentsWithDigestAlgorithmAndItsHashSizeInBits() {
    return Stream.of(
        Arguments.of(DigestAlgorithm.MD5, 128),
        Arguments.of(DigestAlgorithm.SHA_1, 160),
        Arguments.of(DigestAlgorithm.SHA_224, 224),
        Arguments.of(DigestAlgorithm.SHA_256, 256),
        Arguments.of(DigestAlgorithm.SHA_384, 384),
        Arguments.of(DigestAlgorithm.SHA_512, 512),
        Arguments.of(DigestAlgorithm.SHA3_224, 224),
        Arguments.of(DigestAlgorithm.SHA3_256, 256),
        Arguments.of(DigestAlgorithm.SHA3_384, 384),
        Arguments.of(DigestAlgorithm.SHA3_512, 512),
        Arguments.of(DigestAlgorithm.KECCAK_224, 224),
        Arguments.of(DigestAlgorithm.KECCAK_256, 256),
        Arguments.of(DigestAlgorithm.KECCAK_288, 288),
        Arguments.of(DigestAlgorithm.KECCAK_384, 384),
        Arguments.of(DigestAlgorithm.KECCAK_512, 512),
        Arguments.of(DigestAlgorithm.Whirlpool, 512),
        Arguments.of(DigestAlgorithm.Tiger, 192),
        Arguments.of(DigestAlgorithm.SM3, 256)
    );
  }

  @ParameterizedTest
  @EnumSource(DigestAlgorithm.class)
  void producesDigestDifferentToContentWhenDigestingByteArray(DigestAlgorithm algorithm) {
    // Given
    digestService = new JCADigestService(algorithm);

    // When
    final var hash = digestService.digest(CONTENT);

    // Then
    assertThat(hash, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @EnumSource(DigestAlgorithm.class)
  void producesDigestDifferentToContentWhenDigestingStream(DigestAlgorithm algorithm) {
    // Given
    digestService = new JCADigestService(algorithm);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var hash = digestService.digest(contentInputStream);

    // Then
    assertThat(hash, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithDigestAlgorithmAndExpectedHash")
  void producesTheRightHashWhenDigestingByteArray(DigestAlgorithm algorithm, byte[] expectedHash) {
    // Given
    digestService = new JCADigestService(algorithm);

    // When
    final var hash = digestService.digest(CONTENT);

    // Then
    assertThat(hash, is(equalTo(expectedHash)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithDigestAlgorithmAndExpectedHash")
  void producesTheRightHashWhenDigestingStream(DigestAlgorithm algorithm, byte[] expectedHash) {
    // Given
    digestService = new JCADigestService(algorithm);
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var hash = digestService.digest(contentInputStream);

    // Then
    assertThat(hash, is(equalTo(expectedHash)));
  }

  static Stream<Arguments> argumentsWithDigestAlgorithmAndExpectedHash() throws DecoderException {
    return Stream.of(
        Arguments.of(
            DigestAlgorithm.MD5,
            Hex.decodeHex("11294ba715b594ac9666fa0304329948")),
        Arguments.of(
            DigestAlgorithm.SHA_1,
            Hex.decodeHex("cc0639f168304020f9e8ab80961cf41c3b877d16")),
        Arguments.of(
            DigestAlgorithm.SHA_224,
            Hex.decodeHex("d9c782e85927027fe7786ffa627edbd1572b163d90a4da4ef4ed046d")),
        Arguments.of(
            DigestAlgorithm.SHA_256,
            Hex.decodeHex("e0fb432ace777040cca88f0213580f1f7e602928eb5c71097dbde1dc389a7ca7")),
        Arguments.of(
            DigestAlgorithm.SHA_384,
            Hex.decodeHex(
                "dd166ec3fce09053fcc8c08f0cd182b472e46b7a47ca92f43c"
                    + "5d7ab6964f4b910bb01ea3739f5fb1364faeefa7e7bc4e")),
        Arguments.of(
            DigestAlgorithm.SHA_512,
            Hex.decodeHex(
                "4034a6bc9c9a4d719e97ff8f27f266efbdad94e54fe27758ad5"
                    + "a096862bdbea569e6b1b4d74e1d1d5de68e66058a714e133bb"
                    + "b911819fb199e6174240ebdb860")),
        Arguments.of(
            DigestAlgorithm.SHA3_224,
            Hex.decodeHex("6632e68a243a922a0622fcec5c8b2b547500ec285a30efb53ba07659")),
        Arguments.of(
            DigestAlgorithm.SHA3_256,
            Hex.decodeHex("30a9ce72851a93997a4b18c98b4b8c9dc4dd928e939d65db00283024e1e0c72d")),
        Arguments.of(
            DigestAlgorithm.SHA3_384,
            Hex.decodeHex(
                "7c0b0c8e13a542088a3ca00dae1facff8ede7f8ad9c7df"
                    + "80803c2cead11f3f3dd788c63badf1901915997df7da2"
                    + "1cb50")),
        Arguments.of(
            DigestAlgorithm.SHA3_512,
            Hex.decodeHex(
                "c061860b51178e133c31d25f85920d97d98bad1bb422a529"
                    + "79727bb144cbe4394ebb43ced0e8fccf3ee4acf661cae83"
                    + "fb970a8b04975c9b267ad565bd1fd27ab")),
        Arguments.of(
            DigestAlgorithm.KECCAK_224,
            Hex.decodeHex("8106c6080985858f69a284493dd362fd5d49dd6ca4a9c0b3c4347337")),
        Arguments.of(
            DigestAlgorithm.KECCAK_256,
            Hex.decodeHex("472614fec30b8ca6b7ddb15fa3a05a1e01495ff36398eace240dd871c2900e0e")),
        Arguments.of(
            DigestAlgorithm.KECCAK_288,
            Hex.decodeHex(
                "fc0e26eeeab60604bb7f69553bed98c049fdeb2ff273b00eb9b9f418c6e49662dc8e9851")),
        Arguments.of(
            DigestAlgorithm.KECCAK_384,
            Hex.decodeHex(
                "c2a41391ad957d51ca6999cf5bb605b720c51f2bb88d3cee2a89"
                    + "79122b0c0c4140e115adbcd752fe3407b6e987bb3218")),
        Arguments.of(
            DigestAlgorithm.KECCAK_512,
            Hex.decodeHex(
                "6d972d36399e01ad5a2a07dfcf40c798dfd67e93ed1845416f8afb9"
                    + "d953e6fb9c1bebeb751ce5ec4837ea7dc6f902302dd16dac227c114"
                    + "f9b40bb883fc0fa0b3")),
        Arguments.of(
            DigestAlgorithm.Whirlpool,
            Hex.decodeHex(
                "23ed1fa2122af3b7336c9f531c93d9025b774b91eebff4c3a49b0cf9"
                    + "fa516c8c77c072488ec6157da60379c84aab931f2fe77074bb3d129"
                    + "796a6bc8d4839c021")),
        Arguments.of(
            DigestAlgorithm.Tiger,
            Hex.decodeHex("fec60ff87160a26c38b2d861db002fd117fe3f14e14f13c1")),
        Arguments.of(
            DigestAlgorithm.SM3,
            Hex.decodeHex("4ec89f55f5008b83d97be9df51e2126b56344bcb2806ec8131d6b0d17faa17f3"))
    );
  }
}