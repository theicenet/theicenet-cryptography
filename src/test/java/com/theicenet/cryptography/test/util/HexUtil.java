package com.theicenet.cryptography.test.util;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public final class HexUtil {

  private HexUtil() {
  }

  public static byte[] decodeHex(String hex) {
    try {
      return Hex.decodeHex(hex);
    } catch (DecoderException e) {
      throw new RuntimeException(e);
    }
  }
}
