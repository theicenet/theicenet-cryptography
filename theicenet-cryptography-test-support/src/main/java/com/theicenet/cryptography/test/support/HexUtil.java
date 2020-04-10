/*
 * Copyright 2019-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.theicenet.cryptography.test.support;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
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
