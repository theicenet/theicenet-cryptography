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

import java.io.InputStream;

/**
 * A DigestService instance is a component which produces a repeatable and deterministic
 * <b>digest</b> value for a given <b>content</b> by using a <b>cryptographic hash function</b>.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function">Cryptographic hash function</a>
 *
 * @apiNote Any implementation of this interface <b>must</b> be <b>unconditionally thread-safe</b>.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface DigestService {

  /**
   * Produces the <b>digest</b> value of <b>content</b> using a <b>cryptographic hash function</b>.
   *
   * @param content content to hash to produce the <b>digest</b> value
   * @return <b>digest</b> value which is the result of hashing <b>content</b> with a
   *         <b>cryptographic hash function</b>
   */
  byte[] digest(byte[] content);

  /**
   * Produces the <b>digest</b> value of <b>contentInputStream</b> using a <b>cryptographic hash
   * function</b>.
   *
   * @apiNote Once this method returns the input stream must have been closed so it can't be mutated.
   *
   * @param contentInputStream input stream with content to hash to produce the <b>digest</b> value
   * @return <b>digest</b> value which is the result of hashing <b>contentInputStream</b> with a
   *         <b>cryptographic hash function</b>
   */
  byte[] digest(InputStream contentInputStream);
}
