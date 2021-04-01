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
package com.theicenet.cryptography.signature;

import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public abstract class JCASignatureService<T extends Enum<T>> implements SignatureService {

  private final T algorithm;

  protected JCASignatureService(T algorithm) {
    Validate.notNull(algorithm);
    this.algorithm = algorithm;

    // For some sign/verify algorithms it's required Bouncy Castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] content) {
    return sign(privateKey, content, algorithm.toString());
  }

  @Override
  public boolean verify(PublicKey publicKey, byte[] content, byte[] signature) {
    return verify(publicKey, content, signature, algorithm.toString());
  }

  /**
   * @implNote Once this method returns the input stream has been closed as requested
   *           in the API interface.
   */
  @Override
  public byte[] sign(PrivateKey privateKey, InputStream contentInputStream) {
    return sign(privateKey, contentInputStream, algorithm.toString());
  }

  /**
   * @implNote Once this method returns the input stream has been closed as requested
   *           in the API interface.
   */
  @Override
  public boolean verify(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    return verify(publicKey, contentInputStream, signature, algorithm.toString());
  }

  private byte[] sign(PrivateKey privateKey, byte[] content, String algorithm) {
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

  private boolean verify(
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

  private byte[] sign(PrivateKey privateKey, InputStream contentInputStream, String algorithm) {
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

  private boolean verify(
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

  private OutputStream buildSignatureOutputStream(Signature signer) {
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
