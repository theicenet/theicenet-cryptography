package com.theicenet.cryptography.service.pbkd.scrypt;

import static org.mutabilitydetector.unittesting.MutabilityAssert.assertImmutable;

import org.junit.jupiter.api.Test;

class SCryptConfigurationTest {
  @Test
  void checkIsImmutable() {
    assertImmutable(SCryptConfiguration.class);
  }
}