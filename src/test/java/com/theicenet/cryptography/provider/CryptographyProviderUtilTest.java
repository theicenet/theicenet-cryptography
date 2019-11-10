package com.theicenet.cryptography.provider;

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
    int position = CryptographyProviderUtil.addCryptographyProvider(newCryptographyProvider);

    // Then the cryptography provider has been added to the JVM so position is >= 1
    assertThat(position, is(greaterThanOrEqualTo(1)));
  }

  @Test
  void producesPositionEqualsToMinusOneWhenWhenAddingCryptographyProviderWhichDoesExist() {
    // Given a cryptography provider not provided by JVM
    final var newCryptographyProvider =
        new Provider(
            "test-provider-2",
            "1.0",
            "for testing purpose") {};

    assumeFalse(Arrays.asList(Security.getProviders()).contains(newCryptographyProvider));

    CryptographyProviderUtil.addCryptographyProvider(newCryptographyProvider);

    // When adding an existing cryptography provider
    int position = CryptographyProviderUtil.addCryptographyProvider(newCryptographyProvider);

    // Then the cryptography provider has been added to the JVM so position is >= 1
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
  void addsBouncyCastleProperlyWhenAddingBouncyCastleCryptographyProvider() {
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
