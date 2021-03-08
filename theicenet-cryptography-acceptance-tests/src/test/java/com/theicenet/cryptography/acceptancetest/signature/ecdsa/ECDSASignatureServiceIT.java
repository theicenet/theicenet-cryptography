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
package com.theicenet.cryptography.acceptancetest.signature.ecdsa;

import static com.theicenet.cryptography.test.support.KeyPairUtil.toPrivateKey;
import static com.theicenet.cryptography.test.support.KeyPairUtil.toPublicKey;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.signature.SignatureService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
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
class ECDSASignatureServiceIT {

  static {
    // Bouncy Castle is required to reformat the ECDSA public and private keys
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  final String ECDSA = "ECDSA";

  final byte[] CONTENT =
      "Content to be signed to test correctness of the ECDSA sign implementation."
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

  final PublicKey ECDSA_PUBLIC_KEY_BRAINPOOLP256R1 =
      toPublicKey(
          ECDSA_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY,
          ECDSA);
  final PrivateKey ECDSA_PRIVATE_KEY_BRAINPOOLP256R1 =
      toPrivateKey(
          ECDSA_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY,
          ECDSA);

  final byte[] SIGNATURE_SHA1_WITH_ECDSA =
      HexUtil.decodeHex(
          "30450221008481268c784b069e6f3f6413c24404c17ed4d53ebc34f43e2d38938cd4c30a55"
              + "02200d35c055e574d335bcf8f4664f4c88d8d3ccd4834cd76cdd901937012a9dc67c");

  @Autowired
  @Qualifier("ECDSASignature_SHA1withECDSA")
  SignatureService ecdsaSignatureService;

  @Test
  void verifiesProperly() {
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
  void signsProperly() {
    // Given
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
}
