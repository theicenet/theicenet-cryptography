package com.theicenet.cryptography.acceptancetest.signature.dsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.signature.SignatureService;
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
public class DSASignatureServiceIT {

  final String DSA = "DSA";

  final byte[] CONTENT =
      "Content to be signed to test correctness of the DSA sign implementation."
          .getBytes(StandardCharsets.UTF_8);

  final byte[] DSA_PUBLIC_KEY_2048_BITS_BYTE_ARRAY =
      HexUtil.decodeHex(
          "308203473082023906072a8648ce3804013082022c0282010100963d69e42e599e65992e"
              + "f79ceb28866c96749cd1494ac50211af8c6ad23fd1ac0521bd95d9ea0ab83286a5"
              + "4734f7b9b19dae686f4d735472c46644a54d6d3bad392d2a5e3f457ce5c6905a68"
              + "1ac3032e7469c9dd0af43a1d6aea9b28dc5baa668dcf10021c3814678522848dfa"
              + "b8c1c5378f2a59c3abc2cc7026d30a0239c7f785b8e0cdb6138f7cf2bbf4295d26"
              + "8e8d011a01e483b8e840a72cd1da023f9d57e6fad67609bbaa516b61222febe14f"
              + "d05beab78cbe567945b2de0eaef87810c3683f35b50ee333fe1b8fb88faecd8cf8"
              + "a0558bfd4a19b295470affee7fa33e8ff71c8ec6e71aa34785ef9274f2ac655dce"
              + "22557c363ce7fedfd52d965779f4810221009afda2becfe7437b66b367b54549c7"
              + "f57a86bb592bf2db88feee5c42b144d5eb02820100538a5b3d08c41377b52a26bc"
              + "e09d5b77e7ec53e478aae510c54009626347984375df9c8f854bfa7b250590299b"
              + "639378aeadb1e0a4e2617822fc480f6b4eb904aac9d8bd75ab0e29b4bffda0f7e6"
              + "d6d1d420ad6e8d86bd0034d4e224681489f67e503c6bab7cfccf03cebff56e95c1"
              + "a90a860c7e5f3927114a07ff940c7e806e2d29e64d71eaa1926527d57a30214ecf"
              + "678878662dba283a272bfcf127ec22c822066bb9fe517fd974db0bc74769028860"
              + "9fd32ef0d4970ecea7e815a1e72bcc24e9397bb896e25e614db75247d90e4c2d72"
              + "83064cbcd27be69b8e2e07c83c78cba64369072d09f0bea93f74526af7fa658f1c"
              + "cb308fd0e7ac163599f6b05aa2038201060002820101009325df71d0609e7c0304"
              + "846dfdc8a71551277a24ff5b73fb3cd2f556831c2003632e431061db53992d6b6f"
              + "702e8465da2ba810fec4e180000a55846681aeb77b2ad49cf7a1a40c49c552f0e2"
              + "b5b286c050d6e9a8af5ceef2592d3e6ca8f3539580a046e681fa646c100846e7f1"
              + "7fc53b8e1db4c37553c8de7824ce19f34dcdf7113716e7ff7ce9e03a6ff4b05cb4"
              + "39a3b31b8e840fa02907af8fd97bf5e675e2bbd29316a9f0ff87105481b9b602cf"
              + "150a5bd942abcc74f0bdb87b16db007efc6a3499a26b6a016bf90a6264a015a113"
              + "fa5b3b937f1ee12113e584cbbea078c1dffb7cf6df931182bda3c6204023b3687a"
              + "8a528e711b3e62a92886dcd2438661");

  final byte[] DSA_PRIVATE_KEY_2048_BITS_BYTE_ARRAY =
      HexUtil.decodeHex(
          "308202640201003082023906072a8648ce3804013082022c0282010100963d69e42e599e6"
              + "5992ef79ceb28866c96749cd1494ac50211af8c6ad23fd1ac0521bd95d9ea0ab832"
              + "86a54734f7b9b19dae686f4d735472c46644a54d6d3bad392d2a5e3f457ce5c6905"
              + "a681ac3032e7469c9dd0af43a1d6aea9b28dc5baa668dcf10021c3814678522848d"
              + "fab8c1c5378f2a59c3abc2cc7026d30a0239c7f785b8e0cdb6138f7cf2bbf4295d2"
              + "68e8d011a01e483b8e840a72cd1da023f9d57e6fad67609bbaa516b61222febe14f"
              + "d05beab78cbe567945b2de0eaef87810c3683f35b50ee333fe1b8fb88faecd8cf8a"
              + "0558bfd4a19b295470affee7fa33e8ff71c8ec6e71aa34785ef9274f2ac655dce22"
              + "557c363ce7fedfd52d965779f4810221009afda2becfe7437b66b367b54549c7f57"
              + "a86bb592bf2db88feee5c42b144d5eb02820100538a5b3d08c41377b52a26bce09d"
              + "5b77e7ec53e478aae510c54009626347984375df9c8f854bfa7b250590299b63937"
              + "8aeadb1e0a4e2617822fc480f6b4eb904aac9d8bd75ab0e29b4bffda0f7e6d6d1d4"
              + "20ad6e8d86bd0034d4e224681489f67e503c6bab7cfccf03cebff56e95c1a90a860"
              + "c7e5f3927114a07ff940c7e806e2d29e64d71eaa1926527d57a30214ecf67887866"
              + "2dba283a272bfcf127ec22c822066bb9fe517fd974db0bc747690288609fd32ef0d"
              + "4970ecea7e815a1e72bcc24e9397bb896e25e614db75247d90e4c2d7283064cbcd2"
              + "7be69b8e2e07c83c78cba64369072d09f0bea93f74526af7fa658f1ccb308fd0e7a"
              + "c163599f6b05aa20422022066f86f6ba16b288c03dc985df9819d1069b2f2498f6e"
              + "adf7fb3575d71115e7a5");

  final PublicKey DSA_PUBLIC_KEY_2048_BITS;
  final PrivateKey DSA_PRIVATE_KEY_2048_BITS;

  final byte[] SIGNATURE_SHA1_WITH_DSA =
      HexUtil.decodeHex(
          "304402204e44e98b2775b31365fd49c6cf21888362b9c7c5fd6e4152eaf5ca676de6e34b0220"
              + "618985ca7197a804faaae60fee712e5c3a29af942dad60611b90efc2ca965a8c");

  @Autowired
  @Qualifier("DSAKey")
  AsymmetricKeyService dsaKeyService;

  @Autowired
  @Qualifier("DSASignature")
  SignatureService dsaSignatureService;

  DSASignatureServiceIT() throws Exception {
    final var keyFactory = KeyFactory.getInstance(DSA);

    final var x509EncodedKeySpec = new X509EncodedKeySpec(DSA_PUBLIC_KEY_2048_BITS_BYTE_ARRAY);
    DSA_PUBLIC_KEY_2048_BITS = keyFactory.generatePublic(x509EncodedKeySpec);

    final var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(DSA_PRIVATE_KEY_2048_BITS_BYTE_ARRAY);
    DSA_PRIVATE_KEY_2048_BITS = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
  }

  @Test
  void verifiesProperly() {
    // When
    final var verifyingResult =
        dsaSignatureService.verify(
            DSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            SIGNATURE_SHA1_WITH_DSA);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }

  @Test
  void signsProperly() {
    // Given
    final var signature =
        dsaSignatureService.sign(
            DSA_PRIVATE_KEY_2048_BITS,
            CONTENT);

    // When
    final var verifyingResult =
        dsaSignatureService.verify(
            DSA_PUBLIC_KEY_2048_BITS,
            CONTENT,
            signature);

    // Then
    assertThat(verifyingResult, is(equalTo(true)));
  }
}
