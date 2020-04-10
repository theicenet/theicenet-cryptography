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
package com.theicenet.cryptography.key.asymmetric;

import java.security.KeyPair;

/**
 * A AsymmetricKeyService instance is a component which produces a random <b>key pair</b>
 * (public & private) which can be used with <b>public key cryptography</b>
 * (asymmetric cryptography).
 *
 * @see <a href="https://en.wikipedia.org/wiki/Public-key_cryptography">Public-key cryptography</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface AsymmetricKeyService {

  /**
   * Produces a random <b>key pair</b> (public & private) valid to be used with
   * <b>public key cryptography</b>.
   *
   * @apiNote Generated private key must be <b>PKCS #8</b> format
   * @apiNote Generate public key must be <b>X.509</b> format
   *
   * @see <a href="https://en.wikipedia.org/wiki/PKCS">PKCS</a>
   * @see <a href="https://en.wikipedia.org/wiki/PKCS_8">PKCS #8</a>
   * @see <a href="https://en.wikipedia.org/wiki/X.509">X.509</a>
   *
   * @param keyLengthInBits length in bits of the key pair to generate
   * @return random key pair of <b>keyLengthInBits</b> length.
   *         Private key meets <b>PKCS #8</b> and public key meets <b>X.509</b> format
   */
  KeyPair generateKey(int keyLengthInBits);
}
