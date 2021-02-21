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
package com.theicenet.cryptography.signature.rsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.signature.SignatureService;
import com.theicenet.cryptography.util.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * @author Juan Fidalgo
 */
class JCARSASignatureServiceTest {

  final String RSA = "RSA";

  final byte[] CONTENT =
      "Content to be signed to test correctness of the RSA sign implementation."
          .getBytes(StandardCharsets.UTF_8);

  final byte[] DIFFERENT_CONTENT =
      "Totally different content to test that verify detects properly when signature is not correct."
          .getBytes(StandardCharsets.UTF_8);

  final byte[] RSA_PUBLIC_KEY_2048_BITS_BYTE_ARRAY =
      HexUtil.decodeHex(
          "30820122300d06092a864886f70d01010105000382010f003082010a0282010100aba8"
              + "dd0a85fd28c9ea61df4cd5b4aeb6a3fc048cd0549aadf0f379a78f0cfbdc7f1d"
              + "570e9bac0872bb823471229832ef2731b1414c8afd3aa6cb7cc1991045bfbf21"
              + "80a734a04153904ba339c4cd12035345e8b6a15c00395a938244bbf307f113bd"
              + "55fe98e4fdd783c2269e3e2b5dd4e1c6eb7dfed394771723975cbe4937af30ea"
              + "9147347c8a270563da3e1b62a76e29538ade6db7f521465ec5527a568b19674f"
              + "11b6c14027b3507134881cd84ea9921fe4e7d1b7b55eb1e9591d55244c9d278c"
              + "9c4df60807fa15bc6d6b2fb4a713e4fccd3a2fd17dc4d1482a7544c8efa6858d"
              + "d60c0f532822cccf8d94ad961c3de6173dc05d435ba3d0d2f779b026d9050203"
              + "010001");

  final byte[] RSA_PRIVATE_KEY_2048_BITS_BYTE_ARRAY =
      HexUtil.decodeHex(
          "308204c0020100300d06092a864886f70d0101010500048204aa308204a602010002820"
              + "10100aba8dd0a85fd28c9ea61df4cd5b4aeb6a3fc048cd0549aadf0f379a78f0c"
              + "fbdc7f1d570e9bac0872bb823471229832ef2731b1414c8afd3aa6cb7cc199104"
              + "5bfbf2180a734a04153904ba339c4cd12035345e8b6a15c00395a938244bbf307"
              + "f113bd55fe98e4fdd783c2269e3e2b5dd4e1c6eb7dfed394771723975cbe4937a"
              + "f30ea9147347c8a270563da3e1b62a76e29538ade6db7f521465ec5527a568b19"
              + "674f11b6c14027b3507134881cd84ea9921fe4e7d1b7b55eb1e9591d55244c9d2"
              + "78c9c4df60807fa15bc6d6b2fb4a713e4fccd3a2fd17dc4d1482a7544c8efa685"
              + "8dd60c0f532822cccf8d94ad961c3de6173dc05d435ba3d0d2f779b026d905020"
              + "301000102820101009500bbf5e17e71446b5dcf4dcb86cdcd1da4a9726d77b2d8"
              + "5f798854e8b8157b3d1f83acdb75c5d3896da905b748b395a1c8e19ad3cd25a81"
              + "e962d5183027bf8c7f855cb4dc3f95086c51107190c04a1bc4bc78797a2db52ed"
              + "8b731d24a3fd75c673a7cc9a7cd2d69ab9117a746e82414245bfae1b5f1ed50cd"
              + "1c91628da37293ff5b115caf0816ffdd324f2827373da96050e8cdef2fd1179aa"
              + "43a97d70f2137ab7d517fcdbe51f605917781781c2c756dd23f41a61d432a1b4f"
              + "bc0fe42bfcb35c7418dd3a58a86abef8a0c267320fe61d3ac39aa5a5063058471"
              + "3433938e87e359ca354078e34f5cc270d048138e159217a3ae3af189021875481"
              + "9a82c891502818100d306be0143aa02e3f458f390c9d72b4930303b409686e19c"
              + "6885c1d1e0f2e325b3777999009522e982c0dfe4ca3907d6a83f3a929e7af5933"
              + "2c55047a11af9825e57f188345dd475aec337fad83b2fa5d7e6cba9519b353ae1"
              + "6a8cebe50264119991a3db873e748bd7fc33e36a95e267c2f3835114b75297a90"
              + "b606c0b03e79b02818100d03e562ab81d59c48a0871ed3ca328aa9e83f9e4bf48"
              + "757d5b672e515fc7e99dc14cfb4035e1245fa5b7633ea0a45562cb41a4f7b0a5d"
              + "45f3caa91a3b16b2297dc4c3a763e11dff9b81426b61409da10fd24457795652d"
              + "13d01fc15d2940ba72e3419ce34f790d243aaeaac4b3eed06a5829f3f71730c00"
              + "1d9132896a2045bdf02818100ba7f27e6b825053eee90ba59087897b1abdbc451"
              + "d57648e750dc7d297e134a39e47cbf433fe78d9e2f4743d7cffc4cf8216317e1c"
              + "21bcaf297191854e5859062edfbece2c1dcf6ca36742302169d6003c2661f3179"
              + "84a0ab73d215ced86a9f838a63d31b4d501df20524c7bac154cb6d86366da4779"
              + "9786dbe20e6cb3584f2e70281810082b73e7b5e4afe3842b4fe5e7e7ba4614553"
              + "6e9f49faffd50a75003c10357acd8db2f6dbdd764fd0c243154710ab56f5c6c49"
              + "3faeea58963a6bf22e06fd3e24914fdbc8cd07583f44aba4b7a6ba5ab7e92881c"
              + "1aee6a2e1b8bbf032fa95f7a29f7c10dec19ccd094f74900e4ac55b1f9af11d69"
              + "439b85e2e4ac69de9c015a05d02818100992616dbc81f51c5b6e1e2c5cf467675"
              + "954f97fe5b5821e2d4b5ea8933694c0c3553686d25f5093d8b453d3dd5557ca56"
              + "73b3daeca9ffbe9d13890e499ee907cb5e73faf5853e0d57e507fe9cd67254aa3"
              + "5665d74c109c84e02ef91191fd3561f3363cd2a5d9dbc622dfb35e4fa9b9a5bce"
              + "0f4d3349d127f4902bfc2d8b1e980");

  final PublicKey RSA_PUBLIC_KEY_2048_BITS;
  final PrivateKey RSA_PRIVATE_KEY_2048_BITS;

  final byte[] SIGNATURE_SHA1_WITH_RSA =
      HexUtil.decodeHex(
          "2b8aaddc4fe16e678694a2b3aad39a7e71d7d0143725ec0b6019b097c9fc234d7f9c4e30b88"
              + "bee6cdc6e77b096a435716a37222a603f4b3a26aab24f69146604b4b2998b5cef64e6"
              + "90d8fe7f5c3d057edd1bc40b9e70610fea87ef3c1c53185a2c381daf16c4ab5d341ae"
              + "5e790aa9ca4df0ea14bb85ef2b6dcee39c9815388bbde64f6fb3064275ea6f5e545a4"
              + "b47a598a727bd668f8e885f951272d32e0d6aa44ca229b2b47991828d3aba58d3f2e0"
              + "00e8af47463b3350e55244d5d07b881e93e6b2c62ab735c4957b314f2b7289cdfbe43"
              + "a87bf611d1d4ba4572165558f437090823a6df048ab29c12ac389966d1d674822f456"
              + "dd49834a8ae0e19a827f216");

  final byte[] SIGNATURE_SHA256_WITH_RSA =
      HexUtil.decodeHex(
          "45407c0d01d17ceb548d6d4786cafaefd15baa32b3c31fa033277115d42c677fa92513682d6c"
              + "873233e0e005a500a6677ce0057d79ec584606ffbbdc4c8ef47288c1d45a33f7eb4459"
              + "45dfe3ae5623b56fb1996c92f7b546dfc23f0976eb95a158853541d0e1e659fbe9ab56"
              + "a157f7e37b027b5afb454529ff76073ece2322be63e4a5994fa1292df3ecbe1c71c24b"
              + "78302362e2bf1d1166884a14cbdccf625070c9813a4e75c3878530def648e2b619b000"
              + "aba03acbc0b21b34211be8a976b7497ed5fb3f8453ea8c2beb896168e1d0de72e23b4d"
              + "75d617f89f386a7a3f724e769237e2de2e4355d9f2301481a2e10c6bc0b4510da46fbb"
              + "1b34869e25292b8d");

  final byte[] SIGNATURE_SHA512_WITH_RSA =
      HexUtil.decodeHex(
          "2b69b74f26f01918d24976b68928ed4b8c015ad2002d01f9d52e67602c706ce20d4441998d2df"
              + "415d0357a05a4f38d2e0cc01a8191fe762e99384ebd5292869bd06aec86bf53bdf247bb"
              + "64aea6d17af5c212f0d9ec64137c9806d03da36ae8f39738f53af00c1232e4e6e43b54f"
              + "e2231c630bdd838e4970421f50ab92330d6212d4cc215962820c0679408464cb3c9e0cc"
              + "fc47175b9d77fe145b4f9161934d351f7e87a186ec676fe52e458f02d8cff52511b9815"
              + "9c9b93992efa24d7f1a1a5dcf01e094e1d9c3ffd7c7553fc90ee869cc67378f2fb23282"
              + "595215699180f14bbc9fd24be404daae53afb334585260c612cd1e7e51b5111c951a7f8"
              + "42f1b644d");

  JCARSASignatureServiceTest() throws Exception {
    final var keyFactory = KeyFactory.getInstance(RSA);

    final var x509EncodedKeySpec = new X509EncodedKeySpec(RSA_PUBLIC_KEY_2048_BITS_BYTE_ARRAY);
    RSA_PUBLIC_KEY_2048_BITS = keyFactory.generatePublic(x509EncodedKeySpec);

    final var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(RSA_PRIVATE_KEY_2048_BITS_BYTE_ARRAY);
    RSA_PRIVATE_KEY_2048_BITS = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesNotNullWhenSigningByteArray(RSASignatureAlgorithm algorithm) {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // Then
    assertThat(signature, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesNotNullWhenSigningStream(RSASignatureAlgorithm algorithm) {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(signature, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesSizeOfSignatureEqualsToKeyLengthWhenSigningByteArray(RSASignatureAlgorithm algorithm) throws Exception {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // Then
    final var keyFactory = KeyFactory.getInstance(RSA);
    final var rsaPrivateKeySpec = keyFactory.getKeySpec(RSA_PRIVATE_KEY_2048_BITS, RSAPrivateKeySpec.class);

    assertThat(signature.length, is(equalTo(rsaPrivateKeySpec.getModulus().bitLength() / 8)));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesSizeOfSignatureEqualsToKeyLengthWhenSigningStream(RSASignatureAlgorithm algorithm) throws Exception {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    final var keyFactory = KeyFactory.getInstance(RSA);
    final var rsaPrivateKeySpec = keyFactory.getKeySpec(RSA_PRIVATE_KEY_2048_BITS, RSAPrivateKeySpec.class);

    assertThat(signature.length, is(equalTo(rsaPrivateKeySpec.getModulus().bitLength() / 8)));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesSignatureDifferentToClearContentWhenSigningByteArray(RSASignatureAlgorithm algorithm) {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // Then
    assertThat(signature, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producesSignatureDifferentToClearContentWhenSigningStream(RSASignatureAlgorithm algorithm) {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(signature, is(not(equalTo(CONTENT))));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producedSignatureVerifiesToTrueWhenVerifyingByteArrayAndSignatureCorrespondsWithContent(
      RSASignatureAlgorithm algorithm) {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void producedSignatureVerifiesToTrueWhenVerifyingStreamAndSignatureCorrespondsWithContent(
      RSASignatureAlgorithm algorithm) {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT),
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void signatureVerifiesToFalseWhenVerifyingByteArrayAndSignatureDoesNotCorrespondsWithContent(
      RSASignatureAlgorithm algorithm) {
    
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            DIFFERENT_CONTENT,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(false)));
  }

  @ParameterizedTest
  @EnumSource(RSASignatureAlgorithm.class)
  void signatureVerifiesToFalseWhenVerifyingStreamAndSignatureDoesNotCorrespondsWithContent(
      RSASignatureAlgorithm algorithm) {
    // Given
    final SignatureService rsaSignatureService = new JCARSASignatureService(algorithm);

    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            new ByteArrayInputStream(DIFFERENT_CONTENT),
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(false)));
  }

  @Test
  void producesTheRightRSASignatureWhenSigningByteArrayWithSha1WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA1withRSA);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // Then
    assertThat(signature, is(equalTo(SIGNATURE_SHA1_WITH_RSA)));
  }

  @Test
  void producesTheRightRSASignatureWhenSigningStreamWithSha1WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA1withRSA);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(signature, is(equalTo(SIGNATURE_SHA1_WITH_RSA)));
  }

  @Test
  void verifiesProperlyWhenVerifyingByteArrayWithSha1WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA1withRSA);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            SIGNATURE_SHA1_WITH_RSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingStreamWithSha1WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA1withRSA);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT),
            SIGNATURE_SHA1_WITH_RSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void producesTheRightRSASignatureWhenSigningByteArrayWithSha256WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA256withRSA);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // Then
    assertThat(signature, is(equalTo(SIGNATURE_SHA256_WITH_RSA)));
  }

  @Test
  void producesTheRightRSASignatureWhenSigningStreamWithSha256WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA256withRSA);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(signature, is(equalTo(SIGNATURE_SHA256_WITH_RSA)));
  }

  @Test
  void verifiesProperlyWhenVerifyingByteArrayWithSha256WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA256withRSA);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            SIGNATURE_SHA256_WITH_RSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingStreamWithSha256WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA256withRSA);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT),
            SIGNATURE_SHA256_WITH_RSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void producesTheRightRSASignatureWhenSigningByteArrayWithSha512WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // Then
    assertThat(signature, is(equalTo(SIGNATURE_SHA512_WITH_RSA)));
  }

  @Test
  void producesTheRightRSASignatureWhenSigningStreamWithSha512WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var signature =
        rsaSignatureService.sign(
            RSA_PRIVATE_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(signature, is(equalTo(SIGNATURE_SHA512_WITH_RSA)));
  }

  @Test
  void verifiesProperlyWhenVerifyingByteArrayWithSha512WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            SIGNATURE_SHA512_WITH_RSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingStreamWithSha512WithRSA() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var verifyingResult =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT),
            SIGNATURE_SHA512_WITH_RSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void producesTheSameSignatureWhenSigningTwoConsecutiveTimesTheSameContentWithTheSamePrivateKeyForByteArray() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var signature_1 = rsaSignatureService.sign(RSA_PRIVATE_KEY_2048_BITS, CONTENT);
    final var signature_2 = rsaSignatureService.sign(RSA_PRIVATE_KEY_2048_BITS, CONTENT);

    // Then
    assertThat(signature_1, is(equalTo(signature_2)));
  }

  @Test
  void producesTheSameSignatureWhenSigningTwoConsecutiveTimesTheSameContentWithTheSamePrivateKeyForStream() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var signature_1 =
        rsaSignatureService.sign(RSA_PRIVATE_KEY_2048_BITS, new ByteArrayInputStream(CONTENT));
    final var signature_2 =
        rsaSignatureService.sign(RSA_PRIVATE_KEY_2048_BITS, new ByteArrayInputStream(CONTENT));

    // Then
    assertThat(signature_1, is(equalTo(signature_2)));
  }

  @Test
  void producesTheSameSignatureWhenSigningManyConsecutiveTimesTheSameContentWithTheSamePrivateKeyForByteArray() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _100 = 100;

    // When
    final var generatedSignaturesSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    rsaSignatureService.sign(RSA_PRIVATE_KEY_2048_BITS, CONTENT)));

    // Then
    assertThat(generatedSignaturesSet, hasSize(1));
  }

  @Test
  void producesTheSameSignatureWhenSigningManyConsecutiveTimesTheSameContentWithTheSamePrivateKeyForStream() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _100 = 100;

    // When
    final var generatedSignaturesSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    rsaSignatureService.sign(RSA_PRIVATE_KEY_2048_BITS, new ByteArrayInputStream(CONTENT))));

    // Then
    assertThat(generatedSignaturesSet, hasSize(1));
  }

  @Test
  void producesTheSameSignatureWhenSigningConcurrentlyTheSameContentWithTheSamePrivateKeyForByteArray() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _500 = 500;

    // When
    final var generatedSignaturesSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    rsaSignatureService.sign(RSA_PRIVATE_KEY_2048_BITS, CONTENT)));

    // Then
    assertThat(generatedSignaturesSet, hasSize(1));
  }

  @Test
  void producesTheSameSignatureWhenSigningConcurrentlyTheSameContentWithTheSamePrivateKeyForStream() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _500 = 500;

    // When
    final var generatedSignaturesSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    rsaSignatureService.sign(
                        RSA_PRIVATE_KEY_2048_BITS,
                        new ByteArrayInputStream(CONTENT))));

    // Then
    assertThat(generatedSignaturesSet, hasSize(1));
  }

  @Test
  void verifiesProperlyWhenVerifyingTwoConsecutiveTimesTheSameSignatureForByteArray() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var verifyingResult_1 =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            SIGNATURE_SHA512_WITH_RSA);

    final var verifyingResult_2 =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            SIGNATURE_SHA512_WITH_RSA);

    // Then
    assertThat(verifyingResult_1, is(equalTo(true)));
    assertThat(verifyingResult_2, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingTwoConsecutiveTimesTheSameSignatureForStream() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    // When
    final var verifyingResult_1 =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT),
            SIGNATURE_SHA512_WITH_RSA);

    final var verifyingResult_2 =
        rsaSignatureService.verify(
            RSA_PUBLIC_KEY_2048_BITS,
            new ByteArrayInputStream(CONTENT),
            SIGNATURE_SHA512_WITH_RSA);

    // Then
    assertThat(verifyingResult_1, is(equalTo(true)));
    assertThat(verifyingResult_2, is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingManyConsecutiveTimesTheSameSignatureForByteArray() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _100 = 100;

    // When
    final var verifyingResultsSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                rsaSignatureService.verify(
                    RSA_PUBLIC_KEY_2048_BITS,
                    CONTENT,
                    SIGNATURE_SHA512_WITH_RSA));

    // Then
    assertThat(verifyingResultsSet, hasSize(1));
    assertThat(verifyingResultsSet.iterator().next(), is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingManyConsecutiveTimesTheSameSignatureForStream() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _100 = 100;

    // When
    final var verifyingResultsSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                rsaSignatureService.verify(
                    RSA_PUBLIC_KEY_2048_BITS,
                    new ByteArrayInputStream(CONTENT),
                    SIGNATURE_SHA512_WITH_RSA));

    // Then
    assertThat(verifyingResultsSet, hasSize(1));
    assertThat(verifyingResultsSet.iterator().next(), is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingConcurrentlyTheSameSignatureForByteArray() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _500 = 500;

    // When
    final var verifyingResultsSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                rsaSignatureService.verify(
                    RSA_PUBLIC_KEY_2048_BITS,
                    CONTENT,
                    SIGNATURE_SHA512_WITH_RSA));

    // Then
    assertThat(verifyingResultsSet, hasSize(1));
    assertThat(verifyingResultsSet.iterator().next(), is(equalTo(true)));
  }

  @Test
  void verifiesProperlyWhenVerifyingConcurrentlyTheSameSignatureForStream() {
    // Given
    final SignatureService rsaSignatureService =
        new JCARSASignatureService(RSASignatureAlgorithm.SHA512withRSA);

    final var _500 = 500;

    // When
    final var verifyingResultsSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                rsaSignatureService.verify(
                    RSA_PUBLIC_KEY_2048_BITS,
                    new ByteArrayInputStream(CONTENT),
                    SIGNATURE_SHA512_WITH_RSA));

    // Then
    assertThat(verifyingResultsSet, hasSize(1));
    assertThat(verifyingResultsSet.iterator().next(), is(equalTo(true)));
  }
}