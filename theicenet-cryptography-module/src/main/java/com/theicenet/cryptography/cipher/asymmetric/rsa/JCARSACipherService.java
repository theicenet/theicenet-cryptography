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
package com.theicenet.cryptography.cipher.asymmetric.rsa;

import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCipherService;
import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCipherServiceException;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import org.apache.commons.lang.Validate;

/**
 * Java Cryptography Architecture (JCA) based component which encrypts and decrypts using RSA
 * algorithm.
 *
 * @see <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">RSA (cryptosystem)</a>
 * @see <a href="https://en.wikipedia.org/wiki/Java_Cryptography_Architecture">Java Cryptography Architecture (JCA)</a>
 *
 * @implNote This implementation is <b>unconditionally thread-safe</b> as required by the API interface.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class JCARSACipherService implements AsymmetricCipherService {

  private final RSAPadding padding;

  public JCARSACipherService(RSAPadding padding) {
    this.padding = padding;

    // For RSA/NONE/OAEP* it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] encrypt(PublicKey publicKey, byte[] clearContent) {
    return process(Cipher.ENCRYPT_MODE, padding, publicKey, clearContent);
  }

  @Override
  public byte[] decrypt(PrivateKey privateKey, byte[] encryptedContent) {
    return process(Cipher.DECRYPT_MODE, padding, privateKey, encryptedContent);
  }

  private byte[] process(int operationMode, RSAPadding padding, Key key, byte[] content) {
    Validate.notNull(padding);
    Validate.notNull(key);
    Validate.notNull(content);

    try {
      final Cipher cipher = Cipher.getInstance(String.format("RSA/NONE/%s", padding.toString()));
      cipher.init(operationMode, key);

      return cipher.doFinal(content);
    } catch (Exception e) {
      throw new AsymmetricCipherServiceException("Exception processing RSA content", e);
    }
  }
}
