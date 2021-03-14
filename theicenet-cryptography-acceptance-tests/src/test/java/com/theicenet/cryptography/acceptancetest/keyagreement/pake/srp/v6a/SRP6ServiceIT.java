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
package com.theicenet.cryptography.acceptancetest.keyagreement.pake.srp.v6a;

import static com.theicenet.cryptography.test.support.HexUtil.decodeHex;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ClientService;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6VerifierService;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Juan Fidalgo
 */
@SpringBootTest
class SRP6ServiceIT {

  byte[] IDENTITY = "testIdentity".getBytes(StandardCharsets.UTF_8);
  byte[] PASSWORD = "testPassword123".getBytes(StandardCharsets.UTF_8);

  byte[] SALT = decodeHex("73FDFC0AEA06935D2C8C28354B9A1125");

  byte[] EXPECTED_VERIFIER =
      decodeHex(
          "9649D745C12451E7B652BE86FC9C24597881D56231709E5F9197E998FBD7BB6A5A44F1FDFA20A110CABF61E9"
              + "5A4D46BE3699E09791F2346B61CBF8A1B3DC1E91178A52F1A6B6FE6EDA63C68566B7020BB1871D7544"
              + "E4F6F3C4526149258B5B8EDBB4EE0DDB52563ADD314A952DDD8CD4AF7A9E31E8A0738BC310EC6CCA9E"
              + "16003A70947FB9C2C7D4C20806A9D44EE4CBD126A189B4F2906845EDFB3CFEB7794488712B44DB3EFE"
              + "FD47339898653682E95F2B70A38C1F678C90B19579FBC7CE048727B4269B40CC4773FD3324BBB30744"
              + "9EC8E25E52925DF8254AF5B9116A93401263FA451407ECD6F0846423A9531CCFB205A031C4049877FB"
              + "52D232E38AF953");

  @Autowired
  @Qualifier("SRP6Verifier")
  SRP6VerifierService srp6VerifierService;

  @Autowired
  @Qualifier("SRP6Client")
  SRP6ClientService srp6ClientService;

  @Test
  void producesSRP6VerifierWhenGeneratingVerifier() {
    // When
    final var generatedVerifier =
        srp6VerifierService.generateVerifier(SALT, IDENTITY, PASSWORD);

    // The
    assertThat(generatedVerifier, is(equalTo(EXPECTED_VERIFIER)));
  }

}