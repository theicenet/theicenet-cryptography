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
package com.theicenet.cryptography.acceptancetest.cipher.asymmetric.rsa;

import static com.theicenet.cryptography.test.support.KeyPairUtil.toPrivateKey;
import static com.theicenet.cryptography.test.support.KeyPairUtil.toPublicKey;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCipherService;
import com.theicenet.cryptography.test.support.HexUtil;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Juan Fidalgo
 */
@SpringBootTest
public class RSACipherServiceIT {

  final String RSA = "RSA";

  final byte[] CLEAR_CONTENT =
      "Content to be encrypted to test correctness of the RSA encrypt/decrypt implementation."
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

  final PublicKey RSA_PUBLIC_KEY_2048_BITS = toPublicKey(RSA_PUBLIC_KEY_2048_BITS_BYTE_ARRAY, RSA);
  final PrivateKey RSA_PRIVATE_KEY_2048_BITS = toPrivateKey(RSA_PRIVATE_KEY_2048_BITS_BYTE_ARRAY, RSA);

  final byte[] RSA_ENCRYPTED_OAEP_WITH_SHA1_AND_MGF1_PADDING =
      HexUtil.decodeHex(
          "60d49d2ad8679a76377016f06023a1ffcc53943e08c365e217e0dd77dc0c080e27a78b3"
              + "d1336b2f54d4ac63ef1e1d6ead99297fef93bc860daa853ea8cadbf27417e8f2e"
              + "021f09f61e1a2ad6dd9b4b58e4fa7a07ce7dc8a89a89318fea0d6874ef3778344"
              + "468f527a2ddef00a6da958231be21b7edb8d3deec3b3b7038b3f1688ade2ad6df"
              + "34e4646e21977316186521acb54899ed040ca230657899963e1056d0c783b18e5"
              + "0f11ceb1251d039079e1d35deb36fbdbd84947f989f755b3b00c427be8d91dfd2"
              + "cb86c88964c2a70510b85d6ccad6361f50402ccebd6fd3d8ad6c7dae5d705505d"
              + "d8d427a01946121937d4c3536e2ef1388adf0113fb8e7e278d6");

  final byte[] RSA_ENCRYPTED_PKCS1_PADDING =
      HexUtil.decodeHex(
          "a9ce2fcd5056674c8940e519a214073f1a7eb377a5474e20ef95d409c171398ab1d28a5"
              + "a475cd5dfa8c36e7b5b09c063dd9fd2f9b519f1204c6907b71e6b9109576d48a6"
              + "27986dcc581ca9a6b6b56eba7eb02bf43ff7bc795bb83e2226faa7f82810e7a52"
              + "c0c112039df24c5b1419e2b9efd4939795f5a465302cfadc7c025ca6e0e4340af"
              + "a40a5b8efdc5a876944e19e4c8dafdc142bf937aecd5d1c2610812207617f760a"
              + "65ea8d15ac27db6eaeca0154f9b2b7fc71e445ffc8f38d03820349c3fad804fbb"
              + "99cebeb8a0e2d84453cc147416c730315dd4b7a8ce6ac3461235ddedbb0888622"
              + "06529cf54593f3825a30119e699f0a453f141081e4015a0ef87");

  @Autowired
  @Qualifier("RSACipher_OAEPWithSHA1AndMGF1Padding")
  AsymmetricCipherService rsaOAEPWithSHA1AndMGF1PaddingCipherService;

  @Autowired
  @Qualifier("RSACipher_PKCS1Padding")
  AsymmetricCipherService rsaPKCS1PaddingCipherService;

  @Test
  void decryptsProperlyOAEPWithSHA1AndMGF1Padding() {
    // When
    final var decrypted =
        rsaOAEPWithSHA1AndMGF1PaddingCipherService.decrypt(
            RSA_PRIVATE_KEY_2048_BITS,
            RSA_ENCRYPTED_OAEP_WITH_SHA1_AND_MGF1_PADDING);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void encryptsProperlyOAEPWithSHA1AndMGF1Padding() {
    // When
    final var encrypted =
        rsaOAEPWithSHA1AndMGF1PaddingCipherService.encrypt(
            RSA_PUBLIC_KEY_2048_BITS,
            CLEAR_CONTENT);

    // Then
    final var decrypted =
        rsaOAEPWithSHA1AndMGF1PaddingCipherService.decrypt(
            RSA_PRIVATE_KEY_2048_BITS,
            encrypted);

    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void decryptsProperlyPKCS1Padding() {
    // When
    final var decrypted =
        rsaPKCS1PaddingCipherService.decrypt(
            RSA_PRIVATE_KEY_2048_BITS,
            RSA_ENCRYPTED_PKCS1_PADDING);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void encryptsProperlyPKCS1Padding() {
    // When
    final var encrypted =
        rsaPKCS1PaddingCipherService.encrypt(
            RSA_PUBLIC_KEY_2048_BITS,
            CLEAR_CONTENT);

    // Then
    final var decrypted =
        rsaPKCS1PaddingCipherService.decrypt(
            RSA_PRIVATE_KEY_2048_BITS,
            encrypted);

    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }
}
