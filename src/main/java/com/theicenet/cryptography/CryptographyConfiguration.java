package com.theicenet.cryptography;

import com.theicenet.cryptography.provider.CryptographyProvider;
import com.theicenet.cryptography.provider.JCACryptographyProvider;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptographyConfiguration {
  @Bean
  public BouncyCastleProvider bouncyCastleProvider() {
    return new BouncyCastleProvider();
  }

  @Bean
  public CryptographyProvider cryptographyCommon(BouncyCastleProvider bouncyCastleProvider) {
    var cryptographyCommon = new JCACryptographyProvider();
    cryptographyCommon.addCryptographyProvider(bouncyCastleProvider);

    return cryptographyCommon;
  }

  @Bean
  public SecureRandom secureRandom(
      @Value("${cryptography.random.algorithm}") String algorithm) throws NoSuchAlgorithmException {
    return SecureRandom.getInstance(algorithm);
  }
}
