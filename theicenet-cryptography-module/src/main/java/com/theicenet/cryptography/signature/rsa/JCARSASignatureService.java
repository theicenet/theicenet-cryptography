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
package com.theicenet.cryptography.signature.rsa;

import com.theicenet.cryptography.signature.JCASignatureService;

/**
 * Java Cryptography Architecture (JCA) based component which implements <b>RSA</b> digital
 * signature management.
 *
 * @see <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">RSA (cryptosystem)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCARSASignatureService extends JCASignatureService<RSASignatureAlgorithm> {

  public JCARSASignatureService(RSASignatureAlgorithm algorithm) {
    super(algorithm);
  }
}
