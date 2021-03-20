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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.keyagreement.SRP6ClientService;
import com.theicenet.cryptography.keyagreement.SRP6ServerService;
import com.theicenet.cryptography.keyagreement.SRP6VerifierService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Juan Fidalgo
 */
@SpringBootTest
class SRP6ServiceIT {

  byte[] IDENTITY = "acceptanceTestIdentity".getBytes(StandardCharsets.UTF_8);
  byte[] PASSWORD = "acceptanceTestPassword123789$%&".getBytes(StandardCharsets.UTF_8);

  @Autowired
  SRP6VerifierService srp6VerifierService;

  @Autowired
  SRP6ClientService srp6ClientService;

  @Autowired
  SRP6ServerService srp6ServerService;

  @Autowired
  SecureRandomDataService secureRandomDataService;

  @Test
  void producesAValidSRP6ClientServerSignUpAndSignIn() {
    // Given the client generates salt
    final var salt = secureRandomDataService.generateSecureRandomData(16);

    // And Given the client generates verifier and signs up into the server
    final var signUpVerifier =
        srp6VerifierService.generateVerifier(salt, IDENTITY, PASSWORD);

    // When client and server go throw the singing in process to generate shared S
    final var clientValuesA = srp6ClientService.computeValuesA();
    final var serverValuesB = srp6ServerService.computeValuesB(signUpVerifier);

    final var clientS =
        srp6ClientService.computeS(
            salt,
            IDENTITY,
            PASSWORD,
            clientValuesA.getClientPrivateValueA(),
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPublicValueB());

    final var serverS =
        srp6ServerService.computeS(
            signUpVerifier,
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPrivateValueB(),
            serverValuesB.getServerPublicValueB());

    // Then client and server have generated the same shared S
    assertThat(clientS, is(equalTo(serverS)));

    // When client generates client's M1
    final var clientM1 =
        srp6ClientService.computeM1(
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPublicValueB(),
            clientS);

    // Then the server should validate client's M1 as valid
    assertThat(
        srp6ServerService.isValidReceivedM1(
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPublicValueB(),
            serverS,
            clientM1),
        is(true));

    // When server generates server's M2
    final var serverM2 =
        srp6ServerService.computeM2(
            clientValuesA.getClientPublicValueA(),
            serverS,
            clientM1);

    // Then the client should validate the server's M2 as valid
    assertThat(
        srp6ClientService.isValidReceivedM2(
            clientValuesA.getClientPublicValueA(),
            clientS,
            clientM1,
            serverM2),
        is(true));

    // When client and server generate the session key
    final var clientSessionKey = srp6ClientService.computeSessionKey(clientS);
    final var serverSessionKey = srp6ServerService.computeSessionKey(serverS);

    // Then the generated client and server session keys are both identical
    assertThat(clientSessionKey, is(equalTo(serverSessionKey)));
  }
}