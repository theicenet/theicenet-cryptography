package com.theicenet.cryptography.acceptancetest.service.asymmetric.rsa.key;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.service.asymmetric.rsa.key.RSAKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class RSAKeyServiceIT {

  final int KEY_LENGTH_1024_BITS = 1024;

  @Autowired
  RSAKeyService rsaKeyService;

  @Test
  public void producesRSAKeyWhenGeneratingKey() {
    // When
    final var generatedKeyPair = rsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }
}