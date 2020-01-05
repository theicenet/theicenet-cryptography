package com.theicenet.cryptography.acceptancetest.cipher.asymmetric.rsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCipherService;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

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

  final PublicKey RSA_PUBLIC_KEY_2048_BITS;
  final PrivateKey RSA_PRIVATE_KEY_2048_BITS;

  final byte[] RSA_ENCRYPTED_OAEP_WITH_SHA1_AND_MGF1_PADDING =
      HexUtil.decodeHex(
          "1c4514470fa422bb28f233e691f6b00c2a3ae4935b0436a12a8ac045aded8f6e5c99197e20b91"
              + "572e40a465bbb7512fe5552bca690baca673aea21b1b39a43cdf89011e01f6d6e43827d"
              + "05bfb5bcfadb0ef65e70425f3e3d624b21868ca946d9370e1b9559af7cba15246a4b7fb"
              + "65767cc53dd8ec3ba742aeea335b93c1cfb7d0f23ab8845993b7f9680f96c9e015ac35c"
              + "a2d0e17b1b41561fb28e5a72d509e5b6da59b760ba74a9efe751c574c4cf89bd305321b"
              + "aba310fe72bbc5ff15ed7f848490a3b9a0877152697abf4b1754f4f6a7f09d96f729d6d"
              + "a5ade53bc297e6e6c218c379d6d99ab5278c68137d83006f3f7b2921672de3670f1055d"
              + "8e7400222");

  @Autowired
  @Qualifier("RSACipher")
  AsymmetricCipherService rsaCipherService;

  RSACipherServiceIT() throws Exception {
    final var keyFactory = KeyFactory.getInstance(RSA);

    final var x509EncodedKeySpec = new X509EncodedKeySpec(RSA_PUBLIC_KEY_2048_BITS_BYTE_ARRAY);
    RSA_PUBLIC_KEY_2048_BITS = keyFactory.generatePublic(x509EncodedKeySpec);

    final var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(RSA_PRIVATE_KEY_2048_BITS_BYTE_ARRAY);
    RSA_PRIVATE_KEY_2048_BITS = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
  }

  @Test
  void decryptsProperly() {
    // When
    final var decrypted =
        rsaCipherService.decrypt(
            RSA_PRIVATE_KEY_2048_BITS,
            RSA_ENCRYPTED_OAEP_WITH_SHA1_AND_MGF1_PADDING);

    // Then
    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }

  @Test
  void encryptsProperly() {
    // When
    final var encrypted =
        rsaCipherService.encrypt(
            RSA_PUBLIC_KEY_2048_BITS,
            CLEAR_CONTENT);

    // Then
    final var decrypted =
        rsaCipherService.decrypt(
            RSA_PRIVATE_KEY_2048_BITS,
            encrypted);

    assertThat(decrypted, is(equalTo(CLEAR_CONTENT)));
  }
}