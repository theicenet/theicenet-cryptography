package com.theicenet.cryptography;

import java.security.SecureRandom;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan("com.theicenet.cryptography")
public class CryptographyConfiguration {
  @Bean
  @ConditionalOnMissingBean
  public SecureRandom secureRandom() {
    return new SecureRandom();
  }
}
