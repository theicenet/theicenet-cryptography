package com.theicenet.cryptography.digest;

import com.theicenet.cryptography.util.CryptographyProviderUtil;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import org.apache.commons.lang.Validate;

public class JCADigestService implements DigestService {

  private final DigestAlgorithm algorithm;

  public JCADigestService(DigestAlgorithm algorithm) {
    this.algorithm = algorithm;

    // Some of the digest algorithms require bouncy castle
    CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
  }

  @Override
  public byte[] digest(byte[] content) {
    Validate.notNull(content);
    return buildMessageDigest(algorithm).digest(content);
  }

  @Override
  public byte[] digest(InputStream contentInputStream) {
    Validate.notNull(contentInputStream);

    final var messageDigest = buildMessageDigest(algorithm);
    final var digestInputStream =
        new DigestInputStream(
            contentInputStream,
            messageDigest);
    final var nullOutputStream = OutputStream.nullOutputStream();

    try (contentInputStream; digestInputStream; nullOutputStream) {
      digestInputStream.transferTo(nullOutputStream);
    } catch (Exception e) {
      throw new DigestServiceException("Error hashing content", e);
    }

    return messageDigest.digest();
  }

  private MessageDigest buildMessageDigest(DigestAlgorithm algorithm) {
    try {
      return MessageDigest.getInstance(algorithm.toString());
    } catch (Exception e) {
      throw new DigestServiceException("Error creating digester", e);
    }
  }
}
