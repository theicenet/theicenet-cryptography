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
package com.theicenet.cryptography.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class CryptographyProviderUtilTest {

  @Test
  void producesPositionDifferentToMinusOneWhenWhenAddingCryptographyProviderWhichDoesNotExist() {
    // Given a cryptography provider not provided by JVM
    final var newCryptographyProvider =
        new Provider(
            "test-provider-1",
            "1.0",
            "for testing purpose") {};

    assumeFalse(Arrays.asList(Security.getProviders()).contains(newCryptographyProvider));

    // When adding the new cryptography provider
    var position = CryptographyProviderUtil.addCryptographyProvider(newCryptographyProvider);

    // Then the cryptography provider has been added to the JVM so position is >= 1
    assertThat(position, is(greaterThanOrEqualTo(1)));
  }

  @Test
  void producesPositionEqualsToMinusOneWhenWhenAddingCryptographyProviderWhichDoesExist() {
    // Given a cryptography provider provided by JVM
    final var newCryptographyProvider =
        new Provider(
            "test-provider-2",
            "1.0",
            "for testing purpose") {};

    CryptographyProviderUtil.addCryptographyProvider(newCryptographyProvider);

    assumeTrue(Arrays.asList(Security.getProviders()).contains(newCryptographyProvider));

    // When adding an existing cryptography provider
    var position = CryptographyProviderUtil.addCryptographyProvider(newCryptographyProvider);

    // Then the cryptography provider has NOT been added to the JVM so position is -1
    assertThat(position, is(equalTo(-1)));
  }

  @Test
  void addsProviderProperlyWhenAddingCryptographyProviderWhichDoesNotExist() {
    // Given a cryptography provider not provided by JVM
    final var newCryptographyProvider =
        new Provider(
            "test-provider-3",
            "1.0",
            "for testing purpose") {};

    assumeFalse(Arrays.asList(Security.getProviders()).contains(newCryptographyProvider));

    // When adding the new cryptography provider
    CryptographyProviderUtil.addCryptographyProvider(newCryptographyProvider);

    // Then the cryptography provider has been added to the JVM
    assertThat(
        Arrays.asList(Security.getProviders()).contains(newCryptographyProvider),
        is(true));
  }

  @Test
  void addsBouncyCastleProperlyWhenAddingBouncyCastleCryptographyProviderAndItDoesNotExist() {
    // Given Bouncy Castle is not provided by JVM
    final var bouncyCastleProvider = new BouncyCastleProvider();

    assumeTrue(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null);
    assumeFalse(Arrays.asList(Security.getProviders()).contains(bouncyCastleProvider));

    // When adding bouncy castle provider
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();

    // Then the bouncy castle provider has been added to the JVM
    assertThat(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME), is(notNullValue()));
    assertThat(
        Arrays.asList(Security.getProviders()).contains(bouncyCastleProvider),
        is(true));
  }
}
