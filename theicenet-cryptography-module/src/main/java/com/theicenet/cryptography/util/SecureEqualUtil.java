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

import java.util.Optional;

/**
 * This component supports equality verification in constants time (for entities of the same
 * magnitude), independently whether the compared entities are equal or not.
 *
 * Secure equal verification is required to avoid some side channel attacks which
 * take advantage of the information which is leaked when a cryptographic implementation
 * spends different time to be executed, depending on the specific particularities of the
 * input data.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Side-channel_attack">Side-channel attack</a>
 * @see <a href="https://crypto.stanford.edu/~dabo/papers/webtiming.pdf">Exposing Private Information by Timing Web Applications</a>
 *
 * @author Juan Fidalgo
 * @since 1.1.4
 */
public final class SecureEqualUtil {

  private SecureEqualUtil() {}

  /**
   * Checks in a constant time which depends on `a` and `b` lengths, if the byte arrays `a` and `b`
   * are equals. The time spent to check the equality of the byte arrays, does NOT depend on if the
   * byte arrays are equal or not, or how equal or different they are. Time spent to  produce a
   * equality result depends only on `a` and `b` lengths, and for any pair of arrays with the same
   * lengths, the computation will spend always the same time, independently if the byte arrays are
   * equals or not.
   *
   * Note: If the lengths do not match the function returns false immediately.
   *
   * @param a first array
   * @param b second array
   * @return true if both arrays are equal, false otherwise
   */
  public static boolean areEqual(byte[] a, byte[] b) {

    final int aLength = Optional.ofNullable(a).map(aa -> aa.length).orElse(0);
    final int bLength = Optional.ofNullable(b).map(bb -> bb.length).orElse(0);

    if (aLength != bLength) {
      return false;
    }

    byte acc = 0;

    for (int index = 0; index < aLength; index++) {
      acc |= (a[index] ^ b[index]);
    }

    return acc == 0;
  }
}
