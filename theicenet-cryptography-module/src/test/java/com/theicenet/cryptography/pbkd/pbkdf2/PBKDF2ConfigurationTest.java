package com.theicenet.cryptography.pbkd.pbkdf2;

import static org.mutabilitydetector.unittesting.MutabilityAssert.assertImmutable;

import org.junit.jupiter.api.Test;

class PBKDF2ConfigurationTest {
  @Test
  void checkIsImmutable() {
    assertImmutable(PBKDF2Configuration.class);
  }
}