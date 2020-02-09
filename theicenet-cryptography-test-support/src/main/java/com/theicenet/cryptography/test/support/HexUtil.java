package com.theicenet.cryptography.test.support;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.Validate;

public final class HexUtil {

  private HexUtil() {
  }

  public static byte[] decodeHex(String hex) {
    Validate.notEmpty(hex);

    try {
      return Hex.decodeHex(hex);
    } catch (DecoderException e) {
      throw new HexException(e);
    }
  }

  public static String encodeHex(byte[] byteArray) {
    Validate.notNull(byteArray);

    return String.valueOf(Hex.encodeHex(byteArray));
  }
}
