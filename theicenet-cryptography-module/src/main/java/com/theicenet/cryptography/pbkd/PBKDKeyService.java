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
package com.theicenet.cryptography.pbkd;

import java.util.Base64;
import javax.crypto.SecretKey;

/**
 * A PBKDKeyService instance is a component which implements <b>key derivation function</b> (KDF)
 * with a cryptographic hash function to derive a secret key from a secret password or secret value,
 * using a pseudorandom function.
 *
 * KDFs can be used to <b>stretch keys</b> into longer keys or to obtain keys of a required format.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Key_derivation_function">Key derivation function</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface PBKDKeyService {

  /**
   * Generates a <b>repeatable and deterministic</b> key with the requested length
   * <b>keyLengthInBits</b> based on the passed <b>password</b> and <b>salt</b>.
   *
   * @apiNote For a given implementer's configuration it must generate always the same final key
   *          when the in parameters (<b>password</b>, <b>salt</b>, <b>keyLengthInBits</b>) are
   *          the same. Generated final key must be <b>repeatable and deterministic</b>.
   *
   * @param password password to use as foundation to calculate a final key of the requested
   *                 length <b>keyLengthInBits</b>
   * @param salt random salt ito use to calculate a final key of the requested length
   *             <b>keyLengthInBits</b>
   * @param keyLengthInBits length in bits the generated final key must have
   * @return a final <b>repeatable and deterministic</b> key with a length in bits of
   *        <b>keyLengthInBits</b> which has been produced from <b>password</b> and <b>salt</b>
   */
  SecretKey generateKey(String password, byte[] salt, int keyLengthInBits);

  /**
   * Generates a <b>repeatable and deterministic</b> key with the requested length
   * <b>keyLengthInBits</b> based on the passed <b>secret</b> and <b>salt</b>.
   *
   * @implSpec This method is a default implementation which converts the passed <b>secret</b>
   *           to a base64 string and passes it into the method generateKey(String password,...)
   *           to generate the final key.
   * @apiNote In case this default method is overridden by an implementer of this interface, the
   *          overrider method must generate always the same final key when the in
   *          parameters (<b>secret</b>, <b>salt</b>, <b>keyLengthInBits</b>) are
   *          the same. Generated final key must be <b>repeatable and deterministic</b>.
   *
   * @param secret password to use as foundation to calculate a final key of the requested
   *                 length <b>keyLengthInBits</b>
   * @param salt random salt to use to calculate a final key of the requested length
   *             <b>keyLengthInBits</b>
   * @param keyLengthInBits length in bits the generated final key must have
   * @return a final <b>repeatable and deterministic</b> key with a length in bits of
   *        <b>keyLengthInBits</b> which has been produced from <b>secret</b> and <b>salt</b>
   *
   */
  default SecretKey generateKey(byte[] secret, byte[] salt, int keyLengthInBits) {
    return generateKey(
        new String(Base64.getEncoder().encode(secret)),
        salt,
        keyLengthInBits);
  }
}
