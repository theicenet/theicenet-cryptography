package com.theicenet.cryptography.acceptancetest.service.symmetric.aes.key;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.service.symmetric.aes.key.AESKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class JCAAESKeyServiceIT {

  final int KEY_LENGTH_256_BITS = 256;

  @Autowired
  AESKeyService aesKeyService;

  @Test
  void producesKeyWhenGeneratingKey() {
    // When
    final var generatedKey = aesKeyService.generateKey(KEY_LENGTH_256_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }
}