package com.theicenet.cryptography.acceptancetest.key.asymmetric.dsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DSAKeyServiceIT {

  final int KEY_LENGTH_1024_BITS = 1024;

  @Autowired
  @Qualifier("DSAKey")
  AsymmetricKeyService dsaKeyService;

  @Test
  public void producesDSAKeyWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }
}