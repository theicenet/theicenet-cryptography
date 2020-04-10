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
package com.theicenet.cryptography.mac;

import java.io.InputStream;
import javax.crypto.SecretKey;

/**
 * A MacService instance is a component which implements a <b>secret key cryptography</b>
 * (symmetric cryptography) mechanism to work with <b>message authentication code</b> (MAC).
 * This is used to confirm that the message came from the stated sender (its authenticity) and
 * has not been changed (its integrity).
 *
 * @see <a href="https://en.wikipedia.org/wiki/Message_authentication_code">Message authentication code</a>
 * @see <a href="https://en.wikipedia.org/wiki/Symmetric-key_algorithm">Symmetric-key algorithm</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface MacService {

  /**
   * Calculates the <b>message authentication code</b> (MAC) for the passed <b>content</b>
   * using the passed <b>secretKey</b> (secret key cryptography).
   *
   * @param secretKey secret key (symmetric cryptography) to use to calculate the
   *                  <b>message authentication code</b> (MAC)
   * @param content content to calculate the <b>message authentication code</b> (MAC)
   * @return Calculated <b>message authentication code</b> (MAC) which has been produced for
   *         <b>content</b> using the <b>secretKey</b> (symmetric cryptography)
   */
  byte[] calculateMac(SecretKey secretKey, byte[] content);

  /**
   * Calculates the <b>message authentication code</b> (MAC) for the passed input
   * <b>contentInputStream</b> using the passed <b>secretKey</b> (secret key cryptography).
   *
   * @apiNote Once this method returns the input stream must have been closed so it can't be mutated.
   *
   * @param secretKey secret key (symmetric cryptography) to use to calculate the
   *                  <b>message authentication code</b> (MAC)
   * @param contentInputStream input stream with the content to calculate the
   *                           <b>message authentication code</b> (MAC)
   * @return Calculated <b>message authentication code</b> (MAC) which has been produced for
   *         <b>content</b> using the <b>secretKey</b> (symmetric cryptography)
   */
  byte[] calculateMac(SecretKey secretKey, InputStream contentInputStream);
}
