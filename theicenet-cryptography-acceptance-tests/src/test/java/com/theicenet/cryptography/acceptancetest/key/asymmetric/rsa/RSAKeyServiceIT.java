package com.theicenet.cryptography.acceptancetest.key.asymmetric.rsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class RSAKeyServiceIT {

  final int KEY_LENGTH_1024_BITS = 1024;

  @Autowired
  @Qualifier("RSAKey")
  AsymmetricKeyService rsaKeyService;

  @Test
  public void producesRSAKeyWhenGeneratingKey() {
    // When
    final var generatedKeyPair = rsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }
}