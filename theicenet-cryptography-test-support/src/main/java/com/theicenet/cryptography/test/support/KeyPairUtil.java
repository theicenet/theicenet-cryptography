/*
 * Copyright 2019-2021 the original author or authors.
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
package com.theicenet.cryptography.test.support;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.lang3.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public final class KeyPairUtil {
  private KeyPairUtil() {}

  public static PublicKey toPublicKey(byte[] publicKey, String algorithm) {
    Validate.notNull(publicKey);
    Validate.notNull(algorithm);

    try {
      final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
      final KeySpec keySpec = new X509EncodedKeySpec(publicKey);

      return keyFactory.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static PrivateKey toPrivateKey(byte[] privateKey, String algorithm) {
    Validate.notNull(privateKey);
    Validate.notNull(algorithm);

    try {
      final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
      final KeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);

      return keyFactory.generatePrivate(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }
}
