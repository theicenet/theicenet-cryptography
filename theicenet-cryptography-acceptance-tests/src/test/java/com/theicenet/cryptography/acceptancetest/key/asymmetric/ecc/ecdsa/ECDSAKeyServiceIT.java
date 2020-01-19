package com.theicenet.cryptography.acceptancetest.key.asymmetric.ecc.ecdsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ECDSAKeyServiceIT {

  final int KEY_LENGTH_256_BITS = 256;

  @Autowired
  @Qualifier("ECDSAKey")
  AsymmetricKeyService ecdsaKeyService;

  @Test
  public void producesECDSAKeyWhenGeneratingKey() {
    // When
    final var generatedKeyPair = ecdsaKeyService.generateKey(KEY_LENGTH_256_BITS);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }
}