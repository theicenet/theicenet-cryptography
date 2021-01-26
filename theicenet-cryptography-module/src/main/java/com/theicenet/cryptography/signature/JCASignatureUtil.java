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
package com.theicenet.cryptography.signature;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface JCASignatureUtil {

  static byte[] sign(PrivateKey privateKey, byte[] content, String algorithm) {
    Validate.notNull(privateKey);
    Validate.notNull(content);
    Validate.notNull(algorithm);

    try {
      final Signature signer = Signature.getInstance(algorithm);
      signer.initSign(privateKey);
      signer.update(content);

      return signer.sign();
    } catch (Exception e) {
      throw new SignatureServiceException("Exception signing content", e);
    }
  }

  static boolean verify(
      PublicKey publicKey,
      byte[] content,
      byte[] signature,
      String algorithm) {

    Validate.notNull(publicKey);
    Validate.notNull(content);
    Validate.notNull(signature);
    Validate.notNull(algorithm);

    try {
      final Signature verifier = Signature.getInstance(algorithm);
      verifier.initVerify(publicKey);
      verifier.update(content);

      return verifier.verify(signature);
    } catch (Exception e) {
      throw new SignatureServiceException("Exception verifying signature", e);
    }
  }

  static byte[] sign(PrivateKey privateKey, InputStream contentInputStream, String algorithm) {
    Validate.notNull(privateKey);
    Validate.notNull(contentInputStream);
    Validate.notNull(algorithm);

    final Signature signer;
    try(contentInputStream) {
      signer = Signature.getInstance(algorithm);
      signer.initSign(privateKey);
    } catch (Exception e) {
      throw new SignatureServiceException("Exception creating signer", e);
    }

    final OutputStream signerOutputStream = buildSignatureOutputStream(signer);
    try(contentInputStream; signerOutputStream) {
      contentInputStream.transferTo(signerOutputStream);
      return signer.sign();
    } catch (Exception e) {
      throw new SignatureServiceException("Exception signing content", e);
    }
  }

  static boolean verify(
      PublicKey publicKey,
      InputStream contentInputStream,
      byte[] signature,
      String algorithm) {

    Validate.notNull(publicKey);
    Validate.notNull(contentInputStream);
    Validate.notNull(signature);
    Validate.notNull(algorithm);

    final Signature verifier;
    try {
      verifier = Signature.getInstance(algorithm);
      verifier.initVerify(publicKey);
    } catch (Exception e) {
      throw new SignatureServiceException("Exception creating signature verifier", e);
    }

    final OutputStream signerOutputStream = buildSignatureOutputStream(verifier);
    try(contentInputStream; signerOutputStream) {
      contentInputStream.transferTo(signerOutputStream);
      return verifier.verify(signature);
    } catch (Exception e) {
      throw new SignatureServiceException("Exception verifying signature", e);
    }
  }

  static OutputStream buildSignatureOutputStream(Signature signer) {
    return new OutputStream() {
      @Override
      public void write(int b) {
        try {
          signer.update((byte) b);
        } catch (SignatureException e) {
          throw new SignatureServiceException("Exception signing stream", e);
        }
      }
    };
  }
}
