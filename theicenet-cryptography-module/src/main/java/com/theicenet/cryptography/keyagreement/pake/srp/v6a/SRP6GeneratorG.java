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

import java.math.BigInteger;

/**
 * Generator of the multiplicative group 'g'
 *
 * @author Juan Fidalgo
 * @since 1.1.0
 */
interface SRP6GeneratorG {
  //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  BigInteger G_COMMON = BigInteger.valueOf(2);

  //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  BigInteger G_LARGE = BigInteger.valueOf(5);

  //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
  BigInteger G_X_LARGE = BigInteger.valueOf(19);
}
