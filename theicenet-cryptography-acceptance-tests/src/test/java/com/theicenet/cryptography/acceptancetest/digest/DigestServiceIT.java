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
package com.theicenet.cryptography.acceptancetest.digest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.test.support.HexUtil;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Juan Fidalgo
 */
@SpringBootTest
class DigestServiceIT {

  final byte[] CONTENT =
      "Content to digest with different algorithm to check the digesting implementation is correct"
          .getBytes(StandardCharsets.UTF_8);

  final byte[] SHA_1_HASH =
      HexUtil.decodeHex("cc0639f168304020f9e8ab80961cf41c3b877d16");

  final byte[] SHA_256_HASH =
      HexUtil.decodeHex("e0fb432ace777040cca88f0213580f1f7e602928eb5c71097dbde1dc389a7ca7");

  final byte[] SHA_512_HASH =
      HexUtil.decodeHex(
          "4034a6bc9c9a4d719e97ff8f27f266efbdad94e54fe27758ad5a096862bdbea569e6b1b4d74e1d"
              + "1d5de68e66058a714e133bbb911819fb199e6174240ebdb860");

  @Autowired
  @Qualifier("Digest_SHA_1")
  DigestService sha1DigestService;

  @Autowired
  @Qualifier("Digest_SHA_256")
  DigestService sha256DigestService;

  @Autowired
  @Qualifier("Digest_SHA_512")
  DigestService sha512DigestService;

  @Test
  void producesTheRightHashWhenDigestingSha1() {
    // When
    final var hash = sha1DigestService.digest(CONTENT);

    // Then
    assertThat(hash, is(equalTo(SHA_1_HASH)));
  }

  @Test
  void producesTheRightHashWhenDigestingSha256() {
    // When
    final var hash = sha256DigestService.digest(CONTENT);

    // Then
    assertThat(hash, is(equalTo(SHA_256_HASH)));
  }

  @Test
  void producesTheRightHashWhenDigestingSha512() {
    // When
    final var hash = sha512DigestService.digest(CONTENT);

    // Then
    assertThat(hash, is(equalTo(SHA_512_HASH)));
  }
}