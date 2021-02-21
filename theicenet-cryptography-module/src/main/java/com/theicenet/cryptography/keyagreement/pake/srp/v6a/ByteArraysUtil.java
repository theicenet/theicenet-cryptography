/*
 * Copyright 2019-2021 the original author or authors.
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
package com.theicenet.cryptography.keyagreement.pake.srp.v6a;

import com.theicenet.cryptography.util.HexUtil;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
final class ByteArraysUtil {
  private ByteArraysUtil() {}

  /**
   * Return the passed in value as an unsigned byte array.
   *
   * @param value the value to be converted.
   * @return a byte array without a leading zero byte if present in the signed encoding.
   */
  static byte[] toUnsignedByteArray(BigInteger value) {
    Validate.notNull(value);

    final byte[] bytes = value.toByteArray();

    if (bytes[0] == 0 && bytes.length != 1) {
      return ArrayUtils.subarray(bytes, 1, bytes.length);
    }

    return bytes;
  }

  /**
   * Return the passed in unsigned byte array as a positive BigInteger
   *
   * @param byteArray the unsigned byte array to be converted
   * @return a positive BigInteger for the decimal representation of the byteArray
   */
  static BigInteger toBigInteger(byte[] byteArray) {
    Validate.notNull(byteArray);

    return new BigInteger(1, byteArray);
  }

  /**
   * Return the passed in unsigned hexadecimal as a positive BigInteger
   *
   * @param hex the unsigned hexadecimal to be converted
   * @return a positive BigInteger for the decimal representation of the hex
   */
  static BigInteger toBigInteger(String hex) {
    Validate.notNull(hex);

    return new BigInteger(1, HexUtil.decodeHex(hex));
  }

  /**
   * Pads left `byteArray` with value `paddingValue` to a final total length of `paddedLength`
   *
   * @param byteArray byte array to pad left
   * @param paddedLength final length of the resulting array
   * @param paddingValue value to use to pad left
   * @return
   *  - padded left array if paddedLength > byteArray.length
   *  - the same array if paddedLength <= byteArray.length
   */
  static byte[] padLeft(byte[] byteArray, int paddedLength, byte paddingValue) {
    Validate.notNull(byteArray);

    final int byteArrayLength = byteArray.length;

    if (byteArrayLength >= paddedLength) {
      return byteArray;
    }

    byte[] leftPadByteArray = new byte[paddedLength - byteArrayLength];
    if (paddingValue != 0) {
      Arrays.fill(leftPadByteArray, paddingValue);
    }

    return concat(leftPadByteArray, byteArray);
  }

  /**
   * Concatenate multiple byte arrays in sequential order
   *
   * @param byteArrays byte arrays to be concatenated
   * @return
   *  a byte array which is the concatenation of all passed byte arrays in the same order they are
   *  passed in
   *
   */
  static byte[] concat(byte[]... byteArrays) {
    byte[] concatenated = new byte[0];
    for (byte[] byteArray : byteArrays) {
      concatenated = ArrayUtils.addAll(concatenated, byteArray);
    }

    return concatenated;
  }
}
