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
package com.theicenet.cryptography.digest;

import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which calculates hashes.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCADigestService implements DigestService {

  private final DigestAlgorithm algorithm;

  public JCADigestService(DigestAlgorithm algorithm) {
    this.algorithm = algorithm;

    // Some of the digest algorithms require bouncy castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] digest(byte[] content) {
    Validate.notNull(content);
    return buildMessageDigest(algorithm).digest(content);
  }

  /**
   * @implNote Once this method returns the input stream has been closed as requested
   *           in the API interface.
   */
  @Override
  public byte[] digest(InputStream contentInputStream) {
    Validate.notNull(contentInputStream);

    final var messageDigest = buildMessageDigest(algorithm);
    final var digestInputStream =
        new DigestInputStream(
            contentInputStream,
            messageDigest);
    final var nullOutputStream = OutputStream.nullOutputStream();

    try (contentInputStream; digestInputStream; nullOutputStream) {
      digestInputStream.transferTo(nullOutputStream);
    } catch (Exception e) {
      throw new DigestServiceException("Error hashing content", e);
    }

    return messageDigest.digest();
  }

  private MessageDigest buildMessageDigest(DigestAlgorithm algorithm) {
    try {
      return MessageDigest.getInstance(algorithm.toString());
    } catch (Exception e) {
      throw new DigestServiceException("Error creating digester", e);
    }
  }
}
