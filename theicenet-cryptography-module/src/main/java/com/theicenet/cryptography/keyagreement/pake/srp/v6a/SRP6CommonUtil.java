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

import static com.theicenet.cryptography.util.ByteArraysUtil.concat;
import static com.theicenet.cryptography.util.ByteArraysUtil.padLeft;
import static com.theicenet.cryptography.util.ByteArraysUtil.toBigInteger;
import static com.theicenet.cryptography.util.ByteArraysUtil.toUnsignedByteArray;

import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.math.BigInteger;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
final class SRP6CommonUtil {

  static final byte PAD_ZERO = (byte) 0;

  private SRP6CommonUtil() {}

  /**
   * Computes the client 'k' value according to the standard routine: k = H(N, g)
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param digest The Digest used as the hashing function 'H'
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param g The generator of the multiplicative group 'g'
   * @return the resulting 'k' value
   */
  static BigInteger computeK(DigestService digest, BigInteger N, BigInteger g) {
    Validate.notNull(digest);
    Validate.notNull(N);
    Validate.notNull(g);

    final int pathLength = calculatePadLength(N);

    return
        toBigInteger(
            digest.digest(
                concat(
                    padLeft(toUnsignedByteArray(N), pathLength, PAD_ZERO),
                    padLeft(toUnsignedByteArray(g), pathLength, PAD_ZERO))));
  }

  /**
   * Computes the client and server common 'U' value according to the standard routine: U = H(A, B)
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param digest The Digest used as the hashing function 'H'
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param A The client's public value. A mod N must be != 0 (according to specification)
   * @param B The server's public value. B mod N must be != 0 (according to specification)
   * @return the resulting client and server common 'U' value
   */
  static BigInteger computeU(DigestService digest, BigInteger N, BigInteger A, BigInteger B) {
    Validate.notNull(digest);
    Validate.notNull(N);
    Validate.notNull(A);
    Validate.notNull(B);
    Validate.isTrue(isValidPublicValue(N, A));
    Validate.isTrue(isValidPublicValue(N, B));

    final int pathLength = calculatePadLength(N);

    return
        toBigInteger(
            digest.digest(
                concat(
                    padLeft(toUnsignedByteArray(A), pathLength, PAD_ZERO),
                    padLeft(toUnsignedByteArray(B), pathLength, PAD_ZERO))));
  }

  /**
   * Computes the client's evidence message 'M1' according to the standard routine: M1 = H( A | B | S )
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param digest The Digest used as the hashing function 'H'
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param A The client's public value
   * @param B The server's public value
   * @param S The client or server's calculated secret (pre-master secret)
   * @return the calculated client's evidence message 'M1'
   */
  static BigInteger computeM1(
      DigestService digest,
      BigInteger N,
      BigInteger A,
      BigInteger B,
      BigInteger S) {

    Validate.notNull(digest);
    Validate.notNull(N);
    Validate.notNull(A);
    Validate.notNull(B);
    Validate.notNull(S);

    final int pathLength = calculatePadLength(N);

    return
        toBigInteger(
            digest.digest(
                concat(
                    padLeft(toUnsignedByteArray(A), pathLength, PAD_ZERO),
                    padLeft(toUnsignedByteArray(B), pathLength, PAD_ZERO),
                    padLeft(toUnsignedByteArray(S), pathLength, PAD_ZERO))));
  }

  /**
   * Computes the server's evidence message 'M2' according to the standard routine: M2 = H( A | M1 | S )
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param digest The Digest used as the hashing function 'H'
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param A The client's public value
   * @param M1 The client's evidence message
   * @param S The client or server's calculated secret (pre-master secret)
   * @return the calculated server evidence message 'M2'
   */
  static BigInteger computeM2(
      DigestService digest,
      BigInteger N,
      BigInteger A,
      BigInteger M1,
      BigInteger S){

    Validate.notNull(digest);
    Validate.notNull(N);
    Validate.notNull(A);
    Validate.notNull(M1);
    Validate.notNull(S);

    final int pathLength = calculatePadLength(N);

    return
        toBigInteger(
            digest.digest(
                concat(
                    padLeft(toUnsignedByteArray(A), pathLength, PAD_ZERO),
                    padLeft(toUnsignedByteArray(M1), pathLength, PAD_ZERO),
                    padLeft(toUnsignedByteArray(S), pathLength, PAD_ZERO))));
  }

  /**
   * Computes the client and server's common session 'Key' according to the standard routine: Key = H(S)
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param digest The Digest used as the hashing function 'H'
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param S The client or server's calculated secret (pre-master secret)
   * @return the resulting client and server's common 'Key'
   */
  static BigInteger computeSessionKey(DigestService digest, BigInteger N, BigInteger S) {
    Validate.notNull(digest);
    Validate.notNull(N);
    Validate.notNull(S);

    final int padLength = calculatePadLength(N);

    return
        toBigInteger(
            digest.digest(
                padLeft(toUnsignedByteArray(S), padLength, PAD_ZERO)));
  }

  /**
   * Generates a random SRP client or server's private value ('a' or 'b') which is,
   * according to the specification, of at least 256 bits in length
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param randomDataService Source of secure randomness
   * @return the resulting client or server's private value ('a' or 'b').
   */
  static BigInteger generatePrivateValue(BigInteger N, SecureRandomDataService randomDataService) {
    Validate.notNull(N);
    Validate.notNull(randomDataService);

    final int MIN_BITS = 256;

    final int minBits = Math.max(MIN_BITS + 8, N.bitLength()); // MIN_BITS is increased by 8 bits to reduce chances of getting a value which is in effect less than MIN_BITS in length
    final int minBytes = (minBits + 7) / 8;

    BigInteger generatedValue;
    do {
      generatedValue = toBigInteger(randomDataService.generateSecureRandomData(minBytes));
    } while (generatedValue.bitLength() < MIN_BITS); // Iterate till generated values is at least MIN_BITS long. As minBits >= MIN_BITS + 8 there are good chances (1 - 1/2^8) it will get a valid value in the first shot
    
    return generatedValue;
  }

  /**
   * Validates an SRP6 client or server's public value ('A' or 'B')
   *
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param value The public value to validate
   * @return `true` on successful validation, other case `false`
   */
  static boolean isValidPublicValue(BigInteger N, BigInteger value) {
    Validate.notNull(N);
    Validate.notNull(value);

    // check that value mod N != 0
    return !value.mod(N).equals(BigInteger.ZERO);
  }

  /**
   * Computes the padding length according to the specification
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @return the calculated padding length
   */
  static int calculatePadLength(BigInteger N) {
    Validate.notNull(N);

    return (N.bitLength() + 7) / 8;
  }
}
