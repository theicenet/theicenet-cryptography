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
package com.theicenet.cryptography.acceptancetest.keyagreement.ecc.ecdh;

import static com.theicenet.cryptography.test.support.KeyPairUtil.toPrivateKey;
import static com.theicenet.cryptography.test.support.KeyPairUtil.toPublicKey;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.keyagreement.KeyAgreementService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
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
class ECDHKeyServiceIT {

  static {
    // Bouncy Castle is required to reformat the ECDH public and private keys
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  final String ECDH = "ECDH";

  final byte[] ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY_ALICE =
      HexUtil.decodeHex(
          "308188020100301406072a8648ce3d020106092b2403030208010107046d306b020101042031bb"
              + "5a63396638ba89a75640a151a625aa23504ab037e2f983ff799cc658262ba14403420004"
              + "30acba7508c3842bd71992320cb86bd93cb31d46fe76c860fc5d9a17d68e257a3922d39c"
              + "018f2ce4632aa0db89fd4a955889da34556e47ab19adf317673bc75d");

  final byte[] ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY_BOB =
      HexUtil.decodeHex(
          "305a301406072a8648ce3d020106092b240303020801010703420004831d47e0175135e72050c56"
              + "fb9c3a97db56370123b66e5ebec702bcc5889149628822b169c967830499668d78eb5f38e"
              + "c437eef1c8dab3fac2896ec6b5c0f534");

  final PrivateKey ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE =
      toPrivateKey(
          ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY_ALICE,
          ECDH);

  final PublicKey ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB =
      toPublicKey(
          ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY_BOB,
          ECDH);

  final byte[] ECDH_DERIVED_SECRET_KEY =
      HexUtil.decodeHex("3078620e26babfd1200f70a280f7370ef15ce0176e983a2f6803de6eff5dc269");

  @Autowired
  @Qualifier("ECDHKeyAgreement")
  KeyAgreementService ecdhKeyAgreementService;

  @Test
  void producesECDHSecretKeyWhenGeneratingSecretKey() {
    // When
    final var generatedSecretKey =
        ecdhKeyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    // Then
    assertThat(generatedSecretKey, is(equalTo(ECDH_DERIVED_SECRET_KEY)));
  }
}