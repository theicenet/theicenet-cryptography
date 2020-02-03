package com.theicenet.cryptography.acceptancetest.pbkd.argon2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.pbkd.PBKDKeyService;
import com.theicenet.cryptography.test.support.HexUtil;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class PBKDArgon2KeyServiceIT {

  final int KEY_LENGTH_256_BITS = 256;

  final String PASSWORD_1234567890_80_BITS = "1234567890";

  final byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] ARGON2_ID_113_HASH_256_BITS =
      HexUtil.decodeHex("6e9bb67c4531a6c8df76cca86ed5626ef8f0150d98aa3a2ec7eecf6576b17b5c");

  @Autowired
  @Qualifier("PBKDArgon2")
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
    assertThat(generatedKey.getEncoded(), is(equalTo(ARGON2_ID_113_HASH_256_BITS)));
  }
}