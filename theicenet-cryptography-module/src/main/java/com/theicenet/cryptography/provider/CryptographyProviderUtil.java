package com.theicenet.cryptography.provider;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class CryptographyProviderUtil {

  private static final Provider bouncyCastleProvider;

  static {
    bouncyCastleProvider = new BouncyCastleProvider();
  }

  private CryptographyProviderUtil() {
  }

  static int addCryptographyProvider(Provider provider) {
    return Security.addProvider(provider);
  }

  public static void addBouncyCastleCryptographyProvider() {
    addCryptographyProvider(bouncyCastleProvider);
  }
}
