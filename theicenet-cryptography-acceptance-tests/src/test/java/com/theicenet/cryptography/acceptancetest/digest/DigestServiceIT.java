package com.theicenet.cryptography.acceptancetest.digest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.digest.DigestService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DigestServiceIT {

  final byte[] CONTENT =
      "Content to digest with different algorithm to check the digesting implementation is correct"
          .getBytes(StandardCharsets.UTF_8);

  final byte[] SHA_1_HASH =
      HexUtil.decodeHex("cc0639f168304020f9e8ab80961cf41c3b877d16");

  @Autowired
  DigestService digestService;

  @Test
  void producesTheRightHashWhenDigestingByteArray() {
    // When
    final var hash = digestService.digest(CONTENT);

    // Then
    assertThat(hash, is(equalTo(SHA_1_HASH)));
  }

  @Test
  void producesTheRightHashWhenDigestingStream() {
    // Given
    final var clearInputStream = new ByteArrayInputStream(CONTENT);

    // When
    final var hash = digestService.digest(clearInputStream);

    // Then
    assertThat(hash, is(equalTo(SHA_1_HASH)));
  }
}