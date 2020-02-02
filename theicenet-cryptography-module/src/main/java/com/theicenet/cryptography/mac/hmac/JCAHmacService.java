package com.theicenet.cryptography.mac.hmac;

import com.theicenet.cryptography.mac.MacService;
import com.theicenet.cryptography.mac.MacServiceException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.Validate;

public class JCAHmacService implements MacService {

  private final HmacAlgorithm algorithm;

  public JCAHmacService(HmacAlgorithm algorithm) {
    this.algorithm = algorithm;
  }

  @Override
  public byte[] calculateMac(SecretKey secretKey, byte[] content) {
    Validate.notNull(secretKey);
    Validate.notNull(content);

    final var macCalculator = buildMacCalculator(secretKey, algorithm);
    return macCalculator.doFinal(content);
  }

  @Override
  public byte[] calculateMac(SecretKey secretKey, InputStream contentInputStream) {
    Validate.notNull(secretKey);
    Validate.notNull(contentInputStream);

    final var macCalculator = buildMacCalculator(secretKey, algorithm);
    final OutputStream macCalculatorOutputStream = buildMacCalculatorOutputStream(macCalculator);

    try(contentInputStream; macCalculatorOutputStream) {
      contentInputStream.transferTo(macCalculatorOutputStream);
      return macCalculator.doFinal();
    } catch (Exception e) {
      throw new MacServiceException("Exception calculating HMAC", e);
    }
  }

  private Mac buildMacCalculator(SecretKey secretKey, HmacAlgorithm algorithm) {
    final var secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), algorithm.toString());

    final Mac macCalculator;
    try {
      macCalculator = Mac.getInstance(algorithm.toString());
      macCalculator.init(secretKeySpec);
    } catch (Exception e) {
      throw new MacServiceException("Exception creating HMAC calculator", e);
    }

    return macCalculator;
  }

  private static OutputStream buildMacCalculatorOutputStream(Mac macCalculator) {
    return new OutputStream() {
      @Override
      public void write(int b) {
        macCalculator.update((byte) b);
      }
    };
  }
}
