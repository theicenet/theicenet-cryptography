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
package com.theicenet.cryptography.mac.hmac;

import com.theicenet.cryptography.mac.MacService;
import com.theicenet.cryptography.mac.MacServiceException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which implements generation of
 * keyed-hash message authentication code (HMAC)
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @see <a href="https://en.wikipedia.org/wiki/HMAC">HMAC</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCAHmacService implements MacService {

  private final HmacAlgorithm algorithm;

  public JCAHmacService(HmacAlgorithm algorithm) {
    Validate.notNull(algorithm);
    this.algorithm = algorithm;
  }

  @Override
  public byte[] calculateMac(SecretKey secretKey, byte[] content) {
    Validate.notNull(secretKey);
    Validate.notNull(content);

    final Mac macCalculator = buildMacCalculator(secretKey, algorithm);
    return macCalculator.doFinal(content);
  }

  /**
   * @implNote Once this method returns the input stream has been closed as requested
   *           in the API interface.
   */
  @Override
  public byte[] calculateMac(SecretKey secretKey, InputStream contentInputStream) {
    Validate.notNull(secretKey);
    Validate.notNull(contentInputStream);

    final Mac macCalculator = buildMacCalculator(secretKey, algorithm);
    final OutputStream macCalculatorOutputStream = buildMacCalculatorOutputStream(macCalculator);

    try(contentInputStream; macCalculatorOutputStream) {
      contentInputStream.transferTo(macCalculatorOutputStream);
      return macCalculator.doFinal();
    } catch (Exception e) {
      throw new MacServiceException("Exception calculating HMAC", e);
    }
  }

  private Mac buildMacCalculator(SecretKey secretKey, HmacAlgorithm algorithm) {
    final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), algorithm.toString());

    final Mac macCalculator;
    try {
      macCalculator = Mac.getInstance(algorithm.toString());
      macCalculator.init(secretKeySpec);
    } catch (Exception e) {
      throw new MacServiceException("Exception creating HMAC calculator", e);
    }

    return macCalculator;
  }

  private static OutputStream buildMacCalculatorOutputStream(Mac macCalculator) {
    return new OutputStream() {
      @Override
      public void write(int b) {
        macCalculator.update((byte) b);
      }
    };
  }
}
