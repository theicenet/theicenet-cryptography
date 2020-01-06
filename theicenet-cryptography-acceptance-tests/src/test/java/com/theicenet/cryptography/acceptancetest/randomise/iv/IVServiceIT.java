package com.theicenet.cryptography.acceptancetest.randomise.iv;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import com.theicenet.cryptography.randomise.RandomiseService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class IVServiceIT {

  final int IV_LENGTH_32_BYTES = 32;

  @Autowired
  @Qualifier("IV")
  RandomiseService ivService;

  @Test
  void producesIVWhenGeneratingRandom() {
    // When
    final var generatedIV = ivService.generateRandom(IV_LENGTH_32_BYTES);

    // Then
    assertThat(generatedIV, is(notNullValue()));
  }
}