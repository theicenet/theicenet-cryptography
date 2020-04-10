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

import com.theicenet.cryptography.signature.JCASignatureUtil;
import com.theicenet.cryptography.signature.SignatureService;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.commons.lang.Validate;

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
public class JCARSASignatureService implements SignatureService {

  private final RSASignatureAlgorithm algorithm;

  public JCARSASignatureService(RSASignatureAlgorithm algorithm) {
    Validate.notNull(algorithm);
    this.algorithm = algorithm;

    // For some sign/verify algorithms it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] content) {
    return JCASignatureUtil.sign(privateKey, content, algorithm.toString());
  }

  @Override
  public boolean verify(PublicKey publicKey, byte[] content, byte[] signature) {
    return JCASignatureUtil.verify(publicKey, content, signature, algorithm.toString());
  }

  /**
   * @implNote Once this method returns the input stream has been closed as requested
   *           in the API interface.
   */
  @Override
  public byte[] sign(PrivateKey privateKey, InputStream contentInputStream) {
    return JCASignatureUtil.sign(privateKey, contentInputStream, algorithm.toString());
  }

  /**
   * @implNote Once this method returns the input stream has been closed as requested
   *           in the API interface.
   */
  @Override
  public boolean verify(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    return JCASignatureUtil.verify(publicKey, contentInputStream, signature, algorithm.toString());
  }
}
