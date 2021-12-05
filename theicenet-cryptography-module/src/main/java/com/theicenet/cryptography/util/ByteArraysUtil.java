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
package com.theicenet.cryptography.util;

import java.math.BigInteger;
import java.util.Arrays;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public final class ByteArraysUtil {
  private ByteArraysUtil() {}

  /**
   * Return the passed in value as an unsigned byte array.
   *
   * @param value the value to be converted.
   * @return a byte array without a leading zero byte if present in the signed encoding.
   */
  public static byte[] toUnsignedByteArray(BigInteger value) {
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
  public static BigInteger toBigInteger(byte[] byteArray) {
    Validate.notNull(byteArray);

    return new BigInteger(1, byteArray);
  }

  /**
   * Return the passed in unsigned hexadecimal as a positive BigInteger
   *
   * @param hex the unsigned hexadecimal to be converted
   * @return a positive BigInteger for the decimal representation of the hex
   */
  public static BigInteger toBigInteger(String hex) {
    Validate.notNull(hex);

    try {
      return new BigInteger(1, Hex.decodeHex(hex));
    } catch (DecoderException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Pads left <b>byteArray</b> with value <b>paddingValue</b> to a final total length of <b>paddedLength</b>
   *
   * @param byteArray byte array to pad left
   * @param paddedLength final length of the resulting array
   * @param paddingValue value to use to pad left
   * @return
   *  - padded left array if paddedLength {@literal >} byteArray.length
   *  - the same array if paddedLength {@literal <=} byteArray.length
   */
  public static byte[] padLeft(byte[] byteArray, int paddedLength, byte paddingValue) {
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
  public static byte[] concat(byte[]... byteArrays) {
    byte[] concatenated = new byte[0];
    for (byte[] byteArray : byteArrays) {
      concatenated = ArrayUtils.addAll(concatenated, byteArray);
    }

    return concatenated;
  }

  /**
   * Split a <b>byteArray</b> according to the <b>splitIndexes</b>.
   * The element at each index (zero based) is the first element of each resulting subarray.
   *
   * For this given configuration,
   *
   *  - array: {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
   *  - split indexes: 3, 7
   *
   * The resulting sub arrays would be,
   *  {
   *    {0, 1, 2}
   *    {3, 4, 5, 6}
   *    {7, 8, 9, 10}
   *  }
   *
   * @param byteArray byte array to split by <b>splitIndexes</b>
   * @param splitIndexes
   *    Indexes (zero based) where to split the <b>byteArray</b>.
   *    The element at each splitIndex is the first element of each resulting subarray.
   * @return an array of sub arrays with the resulting split
   */
  public static byte[][] split(byte[] byteArray, int... splitIndexes) {
    Validate.notNull(byteArray);

    if (splitIndexes.length == 0) {
      return new byte[][]{byteArray};
    }

    final int byteArrayLength = byteArray.length;

    final int[] splitIndexesSanitisedAndSortedAsc =
        ArrayUtils.addAll(
            Arrays.stream(splitIndexes)
                .filter(index -> index > 0 && index < byteArrayLength)
                .sorted()
                .distinct()
                .toArray(),
            new int[]{byteArrayLength});

    byte[][] splitResult = new byte[splitIndexesSanitisedAndSortedAsc.length][];
    for (int index = 0; index < splitResult.length; index++) {
      final int splitIndex = splitIndexesSanitisedAndSortedAsc[index];

      splitResult[index] =
          ArrayUtils.subarray(
              byteArray,
              index == 0 ? 0 : splitIndexesSanitisedAndSortedAsc[index - 1],
              splitIndex);
    }

    return splitResult;
  }
}
