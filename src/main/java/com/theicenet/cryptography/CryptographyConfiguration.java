package com.theicenet.cryptography;

import java.security.SecureRandom;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptographyConfiguration {
  @Bean
  public SecureRandom secureRandom() {
    return new SecureRandom();
  }
}
