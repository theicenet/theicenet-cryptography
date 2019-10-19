package com.theicenet.cryptography.provider;

import java.security.Provider;
import java.security.Security;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JCACryptographyProvider implements CryptographyProvider {

  private static Logger logger = LoggerFactory.getLogger(JCACryptographyProvider.class);

  @Override
  public void addCryptographyProvider(Provider provider) {
    Security.addProvider(provider);
    logger.info("Added security provider {}", provider);
  }
}
