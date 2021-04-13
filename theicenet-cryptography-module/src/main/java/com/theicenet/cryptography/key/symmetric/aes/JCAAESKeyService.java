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
package com.theicenet.cryptography.key.symmetric.aes;

import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import com.theicenet.cryptography.key.symmetric.SymmetricKeyServiceException;
import com.theicenet.cryptography.random.SecureRandomDataService;
import org.apache.commons.lang.Validate;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Java Cryptography Architecture (JCA) based component which generates AES keys.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">Advanced Encryption Standard</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCAAESKeyService implements SymmetricKeyService {

  private static final String AES = "AES";

  private final SecureRandomDataService secureRandomDataService; // We store the whole SecureRandomDataService, although we are interested only in the embedded SecureRandom provider. The embedded SecureRandom might be recycled over the time following SecureRandomDataService's prediction protection rules

  public JCAAESKeyService(SecureRandomDataService secureRandomDataService) {
    Validate.notNull(secureRandomDataService);
    this.secureRandomDataService = secureRandomDataService;
  }

  @Override
  public SecretKey generateKey(int keyLengthInBits) {
    Validate.isTrue(keyLengthInBits > 0);

    KeyGenerator keyGenerator;
    try {
      keyGenerator = KeyGenerator.getInstance(AES);
    } catch (NoSuchAlgorithmException e) {
      throw new SymmetricKeyServiceException("Exception creating AES key generator", e);
    }
    keyGenerator.init(keyLengthInBits, secureRandomDataService.getSecureRandom());

    return keyGenerator.generateKey();
  }
}
