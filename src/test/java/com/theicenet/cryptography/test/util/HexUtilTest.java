package com.theicenet.cryptography.test.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class HexUtilTest {

  @Test
  void producesTheRightResultWhenDecodingABCDEF() {
    // Given
    final var ABCDEF = "ABCDEF";

    // When
    final var decodedHex = HexUtil.decodeHex(ABCDEF);

    // Then
    assertThat(decodedHex, is(equalTo(new byte[]{-85, -51, -17})));
  }
}