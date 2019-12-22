package com.theicenet.cryptography.service.symmetric.pbkd.pbkdf2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import com.theicenet.cryptography.service.symmetric.pbkd.PBKDKeyService;
import com.theicenet.cryptography.test.util.HexUtil;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class JCAPBKDF2WithHmacSHAKeyServiceIT {

  final int KEY_LENGTH_256_BITS = 256;

  final String PASSWORD_1234567890_80_BITS = "1234567890";

  final byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  static final byte[] PBKDF2_WITH_HMAC_SHA512_HASH_256_BITS =
      HexUtil.decodeHex("fdf8d7ec42d6bef3edb8af5418cbaf3875cc8d80fa74b802caf8f613cdd9dff2");

  @Autowired
  @Qualifier("JCAPBKDF2WithHmacSHAKeyService")
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