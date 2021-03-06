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
package com.theicenet.cryptography.keyagreement.ecc.ecdh;

import static com.theicenet.cryptography.test.support.KeyPairUtil.toPrivateKey;
import static com.theicenet.cryptography.test.support.KeyPairUtil.toPublicKey;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;

import com.theicenet.cryptography.keyagreement.KeyAgreementService;
import com.theicenet.cryptography.test.support.HexUtil;
import com.theicenet.cryptography.test.support.RunnerUtil;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class JCACEDHKeyAgreementServiceTest {

  static {
    // Bouncy Castle is required to reformat the ECDH public and private keys
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  final String ECDH = "ECDH";

  final byte[] ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY_ALICE =
      HexUtil.decodeHex(
          "305a301406072a8648ce3d020106092b24030302080101070342000430acba7508c3842bd719923"
              + "20cb86bd93cb31d46fe76c860fc5d9a17d68e257a3922d39c018f2ce4632aa0db89fd4a95"
              + "5889da34556e47ab19adf317673bc75d");

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

  final byte[] ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY_BOB =
      HexUtil.decodeHex(
          "308188020100301406072a8648ce3d020106092b2403030208010107046d306b0201010420446b35"
              + "84913b39cb26083996c3d976cbe4a64b9f1873cc40cabad3c97b1c40d3a14403420004831d"
              + "47e0175135e72050c56fb9c3a97db56370123b66e5ebec702bcc5889149628822b169c9678"
              + "30499668d78eb5f38ec437eef1c8dab3fac2896ec6b5c0f534");

  final PublicKey ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE =
      toPublicKey(ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY_ALICE, ECDH);
  final PrivateKey ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE =
      toPrivateKey(ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY_ALICE, ECDH);
  final PublicKey ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB =
      toPublicKey(ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BYTE_ARRAY_BOB, ECDH);
  final PrivateKey ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB =
      toPrivateKey(ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BYTE_ARRAY_BOB, ECDH);

  final byte[] ECDH_DERIVED_SECRET_KEY =
      HexUtil.decodeHex("3078620e26babfd1200f70a280f7370ef15ce0176e983a2f6803de6eff5dc269");

  KeyAgreementService keyAgreementService;

  @BeforeEach
  void setUp() {
    keyAgreementService = new JCACEDHKeyAgreementService();
  }

  @Test
  void producesNotNullSecretKeyWhenGeneratingSecretKeyForAlice() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    // Then
    assertThat(generatedSecretKey, is(notNullValue()));
  }

  @Test
  void producesNotNullSecretKeyWhenGeneratingSecretKeyForBob() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE);

    // Then
    assertThat(generatedSecretKey, is(notNullValue()));
  }

  @Test
  void producesNotEmptySecretKeyWhenGeneratingSecretKeyForAlice() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    // Then
    assertThat(generatedSecretKey.length, is(greaterThan(0)));
  }

  @Test
  void producesNotEmptySecretKeyWhenGeneratingSecretKeyForBob() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE);

    // Then
    assertThat(generatedSecretKey.length, is(greaterThan(0)));
  }

  @Test
  void producesSecretKeyWithRightLengthWhenGeneratingSecretKeyForAlice() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    // Then
    assertThat(generatedSecretKey.length, is(equalTo(ECDH_DERIVED_SECRET_KEY.length)));
  }

  @Test
  void producesSecretKeyWithRightLengthWhenGeneratingSecretKeyForBob() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE);

    // Then
    assertThat(generatedSecretKey.length, is(equalTo(ECDH_DERIVED_SECRET_KEY.length)));
  }

  @Test
  void producesTheSameSecretKeyForAliceAndBob() {
    // When
    final var generatedSecretKeyAlice =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    final var generatedSecretKeyBob =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE);

    // Then
    assertThat(generatedSecretKeyAlice, is(equalTo(generatedSecretKeyBob)));
  }

  @Test
  void producesTheRightSecretKeyWhenGeneratingSecretKeyForAlice() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    // Then
    assertThat(generatedSecretKey, is(equalTo(ECDH_DERIVED_SECRET_KEY)));
  }

  @Test
  void producesTheRightSecretKeyWhenGeneratingSecretKeyForBob() {
    // When
    final var generatedSecretKey =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE);

    // Then
    assertThat(generatedSecretKey, is(equalTo(ECDH_DERIVED_SECRET_KEY)));
  }

  @Test
  void producesTheSameSecretKeyWhenGeneratingTwoConsecutiveSecretKeyForAlice() {
    // When
    final var generatedSecretKey_1 =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    final var generatedSecretKey_2 =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB);

    // Then
    assertThat(generatedSecretKey_1, is(equalTo(generatedSecretKey_2)));
  }

  @Test
  void producesTheSameSecretKeyWhenGeneratingTwoConsecutiveSecretKeyForBob() {
    // When
    final var generatedSecretKey_1 =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE);

    final var generatedSecretKey_2 =
        keyAgreementService.generateSecretKey(
            ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
            ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE);

    // Then
    assertThat(generatedSecretKey_1, is(equalTo(generatedSecretKey_2)));
  }

  @Test
  void producesTheSameSecretKeyWhenGeneratingManyConsecutiveSecretKeyForAlice() {
    // Given
    final var _100 = 100;

    // When generating consecutive secret key for alice
    final var generatedSecretKeysSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    keyAgreementService.generateSecretKey(
                        ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
                        ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB)));

    // Then all secret keys generated are the same
    assertThat(generatedSecretKeysSet, hasSize(1));
  }

  @Test
  void producesTheSameSecretKeyWhenGeneratingManyConsecutiveSecretKeyForBob() {
    // Given
    final var _100 = 100;

    // When generating consecutive secret key for bob
    final var generatedSecretKeysSet =
        RunnerUtil.runConsecutivelyToSet(
            _100,
            () ->
                HexUtil.encodeHex(
                    keyAgreementService.generateSecretKey(
                        ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
                        ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE)));

    // Then all secret keys generated are the same
    assertThat(generatedSecretKeysSet, hasSize(1));
  }

  @Test
  void producesTheSameSecretKeyWhenGeneratingConcurrentlyManySecretKeyForAlice() {
    // Given
    final var _500 = 500;

    // When generating concurrently secret key for alice
    final var generatedSecretKeysSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    keyAgreementService.generateSecretKey(
                        ECDH_PRIVATE_KEY_BRAINPOOLP256R1_ALICE,
                        ECDH_PUBLIC_KEY_BRAINPOOLP256R1_BOB)));

    // Then all secret keys generated are the same
    assertThat(generatedSecretKeysSet, hasSize(1));
  }

  @Test
  void producesTheSameSecretKeyWhenGeneratingConcurrentlyManySecretKeyForBob() {
    // Given
    final var _500 = 500;

    // When generating concurrently secret key for alice
    final var generatedSecretKeysSet =
        RunnerUtil.runConcurrentlyToSet(
            _500,
            () ->
                HexUtil.encodeHex(
                    keyAgreementService.generateSecretKey(
                        ECDH_PRIVATE_KEY_BRAINPOOLP256R1_BOB,
                        ECDH_PUBLIC_KEY_BRAINPOOLP256R1_ALICE)));

    // Then all secret keys generated are the same
    assertThat(generatedSecretKeysSet, hasSize(1));
  }
}