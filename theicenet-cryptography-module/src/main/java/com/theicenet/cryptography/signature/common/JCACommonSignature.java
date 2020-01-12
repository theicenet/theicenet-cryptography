package com.theicenet.cryptography.signature.common;

import com.theicenet.cryptography.signature.dsa.DSASignatureServiceException;
import com.theicenet.cryptography.signature.rsa.RSASignatureServiceException;
import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.apache.commons.lang.Validate;

public final class JCACommonSignature {
  private JCACommonSignature() {
  }

  public static byte[] sign(PrivateKey privateKey, byte[] content, String algorithm) {
    Validate.notNull(privateKey);
    Validate.notNull(content);
    Validate.notNull(algorithm);

    try {
      final var signer = Signature.getInstance(algorithm);
      signer.initSign(privateKey);
      signer.update(content);

      return signer.sign();
    } catch (Exception e) {
      throw new SignatureServiceException("Exception signing content", e);
    }
  }

  public static byte[] sign(PrivateKey privateKey, InputStream contentInputStream, String algorithm) {
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

  public static boolean verify(
      PublicKey publicKey,
      byte[] content,
      byte[] signature,
      String algorithm) {

    Validate.notNull(publicKey);
    Validate.notNull(content);
    Validate.notNull(signature);
    Validate.notNull(algorithm);

    try {
      final var verifier = Signature.getInstance(algorithm);
      verifier.initVerify(publicKey);
      verifier.update(content);

      return verifier.verify(signature);
    } catch (Exception e) {
      throw new SignatureServiceException("Exception verifying signature", e);
    }
  }

  public static boolean verify(
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
      throw new SignatureServiceException("Exception creating verifier", e);
    }

    final OutputStream signerOutputStream = buildSignatureOutputStream(verifier);
    try(contentInputStream; signerOutputStream) {
      contentInputStream.transferTo(signerOutputStream);
      return verifier.verify(signature);
    } catch (Exception e) {
      throw new SignatureServiceException("Exception verifying content", e);
    }
  }

  private static OutputStream buildSignatureOutputStream(Signature signer) {
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
