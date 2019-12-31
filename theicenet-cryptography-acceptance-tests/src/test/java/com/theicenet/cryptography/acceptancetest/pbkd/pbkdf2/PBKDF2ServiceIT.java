package com.theicenet.cryptography.acceptancetest.pbkd.pbkdf2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.acceptancetest.util.HexUtil;
import com.theicenet.cryptography.pbkd.PBKDKeyService;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class PBKDF2ServiceIT {

  final int KEY_LENGTH_256_BITS = 256;

  final String PASSWORD_1234567890_80_BITS = "1234567890";

  final byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  static final byte[] PBKDF2_WITH_HMAC_SHA512_HASH_256_BITS =
      HexUtil.decodeHex("828ecba1f92cf57631611736039ac9cc6cbe9c5f8fe28811c53909dbb5d06858");

  @Autowired
  @Qualifier("PBKDF2")
  PBKDKeyService pbkdKeyService;

  @Test
  void producesTheRightKeyWhenGeneratingKey() {
    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS);

    // Then
    assertThat(generatedKey.getEncoded(), is(equalTo(PBKDF2_WITH_HMAC_SHA512_HASH_256_BITS)));
  }
}