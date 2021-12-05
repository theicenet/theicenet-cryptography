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

import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil.isValidPublicValue;

import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import java.math.BigInteger;
import org.apache.commons.lang3.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
final class SRP6ServerUtil {
  private SRP6ServerUtil() {}

  /**
   * Computes the server's public value 'B' according to the standard routine: B = ((k*v) + (g^b)) mod N
   *
   * (Please note that RFC 5054 specification says B = (k*v) + ((g^b) mod N), but as the
   * Errata ID 4546 clarifies, it should say B = ((k*v) + (g^b)) mod N)
   *
   * Using modular arithmetic the standard routine can be reduced to the equivalent,
   *
   *  B = ((k*v) + ((g^b) mod N)) mod N
   *
   * Which is a more convenient formula to compute the server's public value 'B' when working
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
   * @param v The password verifier 'v'.
   * @param b The server's private value
   *          computed by {@link com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil#generatePrivateValue(BigInteger, SecureRandomDataService)  generatePrivateValue(N, random)}
   * @return the resulting server's public value 'B'
   */
  static BigInteger computeB(
      BigInteger N,
      BigInteger g,
      BigInteger k,
      BigInteger v,
      BigInteger b) {

    Validate.notNull(N);
    Validate.notNull(g);
    Validate.notNull(k);
    Validate.notNull(v);
    Validate.notNull(b);

    return g.modPow(b, N).add(v.multiply(k)).mod(N);
  }

  /**
   * Computes the server's pre-master secret 'S' according the standard routine: S = ((A * (v^u)) ^ b) mod N
   *
   * Using modular arithmetic the standard routine can be reduced to the equivalent,
   *
   * S = ((A * ((v^u) mod N)) ^ b) mod N
   *
   * Which is a more convenient formula to compute the server's pre-master secret 'S' when working
   * with BigIntegers and exponentiation in Java.
   *
   * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
   * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
   * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
   *
   * @param N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
   * @param v The password verifier 'v'
   * @param u The common 'u' value
   *          computed by {@link com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil#computeU(DigestService, BigInteger, BigInteger, BigInteger) computeU(digest, N, A, B)}
   * @param b The server's private value
   *          computed by {@link com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6CommonUtil#generatePrivateValue(BigInteger, SecureRandomDataService)  generatePrivateValue(N, random)}
   * @param A The client's public value 'A'. A mod N must be != 0 (according to specification)
   * @return the resulting pre-master secret 'S'
   */
  static BigInteger computeS(
      BigInteger N,
      BigInteger v,
      BigInteger u,
      BigInteger b,
      BigInteger A) {

    Validate.notNull(N);
    Validate.notNull(v);
    Validate.notNull(u);
    Validate.notNull(b);
    Validate.notNull(A);
    Validate.isTrue(isValidPublicValue(N, A));

    return v.modPow(u, N).multiply(A).modPow(b, N);
  }
}
