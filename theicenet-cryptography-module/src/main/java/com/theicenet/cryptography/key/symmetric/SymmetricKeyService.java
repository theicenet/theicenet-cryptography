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
package com.theicenet.cryptography.key.symmetric;

import javax.crypto.SecretKey;

/**
 * A SymmetricKeyService instance is a component which produces a random <b>private key</b>
 * which can be used with <b>secret key cryptography</b> (symmetric cryptography).
 *
 * @see <a href="https://en.wikipedia.org/wiki/Symmetric-key_algorithm">Symmetric-key algorithm</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface SymmetricKeyService {

  /**
   * Produces a random <b>private key</b> valid to be used with <b>secret key cryptography</b>.
   *
   * @param keyLengthInBits length in bits of the key pair to generate
   * @return random private key of <b>keyLengthInBits</b> length.
   */
  SecretKey generateKey(int keyLengthInBits);
}
