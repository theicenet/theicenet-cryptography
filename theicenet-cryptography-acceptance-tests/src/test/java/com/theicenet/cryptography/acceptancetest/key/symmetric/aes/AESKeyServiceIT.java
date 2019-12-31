package com.theicenet.cryptography.acceptancetest.key.symmetric.aes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AESKeyServiceIT {

  final int KEY_LENGTH_256_BITS = 256;

  @Autowired
  @Qualifier("AESKey")
  SymmetricKeyService aesKeyService;

  @Test
  void producesKeyWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_256_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }
}