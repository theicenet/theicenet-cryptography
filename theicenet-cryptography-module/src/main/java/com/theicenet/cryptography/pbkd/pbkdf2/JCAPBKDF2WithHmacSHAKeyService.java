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
package com.theicenet.cryptography.pbkd.pbkdf2;

import com.theicenet.cryptography.pbkd.PBKDKeyService;
import com.theicenet.cryptography.pbkd.PBKDKeyServiceException;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which implements PBKDF2 algorithm for
 * password based key derivation (PBKD).
 *
 * @see <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCAPBKDF2WithHmacSHAKeyService implements PBKDKeyService {

  private final PBKDF2Configuration pbkdf2Configuration;

  public JCAPBKDF2WithHmacSHAKeyService(PBKDF2Configuration pbkdf2Configuration) {
    Validate.notNull(pbkdf2Configuration);
    this.pbkdf2Configuration = pbkdf2Configuration;

    // For PBKDF2WithHmacSHA3-XXX it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  /**
   *
   * @implNote For a given component configuration, the generated final key is repeatable and
   *           deterministic as requested in the API interface. Same entry produces always the
   *           same result.
   */
  @Override
  public SecretKey generateKey(String password, byte[] salt, int keyLengthInBits) {
    Validate.notNull(password);
    Validate.notNull(salt);
    Validate.isTrue(keyLengthInBits > 0);

    try {
      final PBEKeySpec pbeKeySpec =
          new PBEKeySpec(
              password.toCharArray(),
              salt,
              pbkdf2Configuration.getIterations(),
              keyLengthInBits);

      return generateKey(pbkdf2Configuration.getAlgorithm(), pbeKeySpec);
    } catch (Exception e) {
      throw new PBKDKeyServiceException("Exception generating PBKDF2 key", e);
    }
  }

  private SecretKey generateKey(
      String algorithm,
      PBEKeySpec pbeKeySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {

    return SecretKeyFactory.getInstance(algorithm).generateSecret(pbeKeySpec);
  }
}
