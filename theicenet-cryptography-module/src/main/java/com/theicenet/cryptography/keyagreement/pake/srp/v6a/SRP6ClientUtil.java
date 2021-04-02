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
import static com.theicenet.cryptography.util.ByteArraysUtil.toBigInteger;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.isValidPublicValue;

import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.math.BigInteger;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
final class SRP6ClientUtil {
  private SRP6ClientUtil() {}

  /**
   * Creates a new SRP 'verifier' according to the standard routine v = (g^x) mod N
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param g The generator of the multiplicative group 'g'
   * @param x The client's 'x' value
   *          computed by {@link #computeX(DigestService, byte[], byte[], byte[]) computeX(digest, salt, identity, password))}
   * @return The verifier for use in future SRP authentication
   */
  static BigInteger generateVerifier(BigInteger N, BigInteger g, BigInteger x) {
    Validate.notNull(N);
    Validate.notNull(g);
    Validate.notNull(x);

    return g.modPow(x, N);
  }

  /**
   * Computes the client's 'x' value according to the standard routine: x = H(salt | H ( identity | ":" | password) )
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param digest The Digest used as the hashing function 'H'
   * @param salt random 'salt' common to client and server
   * @param identity client's 'identity'
   * @param password client's 'password'
   * @return the resulting client 'x' value
   *
   */
  static BigInteger computeX(DigestService digest, byte[] salt, byte[] identity, byte[] password) {
    Validate.notNull(digest);
    Validate.notNull(salt);
    Validate.notNull(identity);
    Validate.notNull(password);

    return
        toBigInteger(
            digest.digest(
                concat(
                    salt,
                    digest.digest(concat(identity, new byte[]{(byte)':'}, password)))));
  }

  /**
   * Computes the client's public value 'A' according to the standard routine: A = (g^a) mod N
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param g The generator of the multiplicative group 'g'
   * @param a The client's private value
   *          computed by {@link com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil#generatePrivateValue(BigInteger, SecureRandomDataService)  generatePrivateValue(N, random)}
   * @return the resulting client's public value 'A'
   */
  static BigInteger computeA(BigInteger N, BigInteger g, BigInteger a) {
    Validate.notNull(N);
    Validate.notNull(g);
    Validate.notNull(a);

    return g.modPow(a, N);
  }

  /**
   * Computes the client's pre-master secret 'S' according the standard routine: S = ((B - (k * (g^x))) ^ (a + (u * x))) mod N
   *
   * Using modular arithmetic the standard routine can be reduced to the equivalent,
   *
   *  S = ((B - (k * ((g^x) mod N))) ^ (a + (u * x))) mod N
   *
   * Which is a more convenient formula to compute the client's pre-master secret 'S' when working
   * with BigIntegers and exponentiation in Java.
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param g The generator of the multiplicative group 'g'
   * @param k The common 'k' value
   *          computed by {@link com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil#computeK(DigestService, BigInteger, BigInteger)} computeK(digest, N, g)}
   * @param x The client's 'x' value
   *          computed by {@link #computeX(DigestService, byte[], byte[], byte[]) computeX(digest, salt, identity, password))}
   * @param u The common 'u' value
   *          computed by {@link com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil#computeU(DigestService, BigInteger, BigInteger, BigInteger) computeU(digest, N, A, B)}
   * @param a The client's private value
   *          computed by {@link com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil#generatePrivateValue(BigInteger, SecureRandomDataService)  generatePrivateValue(N, random)}
   * @param B The server's public value 'B'. B mod N must be != 0 (according to specification)
   * @return the resulting pre-master secret 'S'
   */
  static BigInteger computeS(
      BigInteger N,
      BigInteger g,
      BigInteger k,
      BigInteger x,
      BigInteger u,
      BigInteger a,
      BigInteger B) {

    Validate.notNull(N);
    Validate.notNull(g);
    Validate.notNull(k);
    Validate.notNull(x);
    Validate.notNull(u);
    Validate.notNull(a);
    Validate.notNull(B);
    Validate.isTrue(isValidPublicValue(N, B));

    final BigInteger exp = u.multiply(x).add(a);
    final BigInteger tmp = g.modPow(x, N).multiply(k);
    return B.subtract(tmp).modPow(exp, N);
  }
}
