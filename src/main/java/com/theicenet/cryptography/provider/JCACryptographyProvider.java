package com.theicenet.cryptography.provider;

import java.security.Provider;
import java.security.Security;
import org.springframework.stereotype.Component;

@Component
public class JCACryptographyProvider implements CryptographyProvider {
  @Override
  public void addCryptographyProvider(Provider provider) {
    Security.addProvider(provider);
  }
}
