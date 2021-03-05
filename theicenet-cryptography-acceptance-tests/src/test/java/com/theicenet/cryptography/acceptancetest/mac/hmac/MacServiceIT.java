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
package com.theicenet.cryptography.acceptancetest.mac.hmac;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.mac.MacService;
import com.theicenet.cryptography.test.support.HexUtil;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Juan Fidalgo
 */
@SpringBootTest
class MacServiceIT {

  final String AES = "AES";

  final byte[] CONTENT =
      "Content to MAC with HMAC SHA128 to test mac calculator correctness"
          .getBytes(StandardCharsets.UTF_8);

  final SecretKey SECRET_KEY_1234567890123456_128_BITS =
      new SecretKeySpec(
          "1234567890123456".getBytes(StandardCharsets.UTF_8),
          AES);

  final byte[] HMAC_SHA_1 =
      HexUtil.decodeHex("a2fdff1710aef9c827262bd54dc0f653a7050672");

  @Autowired
  MacService macService;

  @Test
  void producesTheRightMacWhenCalculatingMacForByteArray() {
    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            CONTENT);

    // Then
    assertThat(mac, is(equalTo(HMAC_SHA_1)));
  }

  @Test
  void producesTheRightMacWhenCalculatingMacStream() {
    // Given
    final var contentInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var mac =
        macService.calculateMac(
            SECRET_KEY_1234567890123456_128_BITS,
            contentInputStream);

    // Then
    assertThat(mac, is(equalTo(HMAC_SHA_1)));
  }
}