package com.theicenet.cryptography.service.pbkd.argon2;

import static org.mutabilitydetector.unittesting.MutabilityAssert.assertImmutable;

import org.junit.jupiter.api.Test;

class Argon2ConfigurationTest {

  @Test
  void checkIsImmutable() {
    assertImmutable(Argon2Configuration.class);
  }
}