package com.theicenet.cryptography.provider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JCACryptographyProviderTest {

  CryptographyProvider cryptographyProvider;

  @BeforeEach
  void setUp() {
    cryptographyProvider = new JCACryptographyProvider();
  }

  @Test
  void addsProviderProperlyWhenAddingCryptographyProvider() {
    // Given a cryptography provider not provided by JVM
    final var newCryptographyProvider =
        new Provider(
            "test-provider",
            "1.0",
            "for testing purpose") {};

    assumeFalse(Arrays.asList(Security.getProviders()).contains(newCryptographyProvider));

    // When adding the new cryptography provider
    cryptographyProvider.addCryptographyProvider(newCryptographyProvider);

    // Then the cryptography provider has been added to the JVM
    assertThat(
        Arrays.asList(Security.getProviders()).contains(newCryptographyProvider),
        is(true));
  }
}
