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

import static com.theicenet.cryptography.util.ByteArraysUtil.toBigInteger;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GeneratorG.G_COMMON;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GeneratorG.G_LARGE;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6GeneratorG.G_X_LARGE;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_1024;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_1536;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_2048;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_3072;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_4096;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_6144;
import static com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6SafePrimeN.N_8192;

import java.math.BigInteger;

/**
 * Standard safe precomputed group parameters,
 *
 *  - N The safe prime parameter 'N' (a prime of the form N=2q+1, where q is also prime)
 *  - g The generator of the multiplicative group 'g'
 *
 *
 * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
 * @see <a href="https://tools.ietf.org/html/rfc2945">Specification: RFC 2945</a>
 * @see <a href="https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol">Secure Remote Password protocol</a>
 *
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public enum SRP6StandardGroup {
  SG_1024(toBigInteger(N_1024), G_COMMON),  //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  SG_1536(toBigInteger(N_1536), G_COMMON),  //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  SG_2048(toBigInteger(N_2048), G_COMMON),  //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  SG_3072(toBigInteger(N_3072), G_LARGE),   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  SG_4096(toBigInteger(N_4096), G_LARGE),   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  SG_6144(toBigInteger(N_6144), G_LARGE),   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  SG_8192(toBigInteger(N_8192), G_X_LARGE); //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)

  private final BigInteger N;
  private final BigInteger g;

  SRP6StandardGroup(BigInteger N, BigInteger g) {
    this.N = N;
    this.g = g;
  }

  public BigInteger getN() {
    return N;
  }

  public BigInteger getG() {
    return g;
  }
}
