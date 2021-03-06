/*
 * Copyright 2019-2020 the original author or authors.
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
package com.theicenet.cryptography.util;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
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
