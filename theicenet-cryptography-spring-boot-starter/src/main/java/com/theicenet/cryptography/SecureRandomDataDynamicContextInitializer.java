/*
 * Copyright 2019-2021 the original author or authors.
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
package com.theicenet.cryptography;

import com.theicenet.cryptography.exception.DynamicContextInitializerException;
import com.theicenet.cryptography.random.JCASecureRandomDataService;
import com.theicenet.cryptography.random.SecureRandomAlgorithm;
import com.theicenet.cryptography.random.SecureRandomCapability;
import com.theicenet.cryptography.util.PropertiesUtil;
import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Optional;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class SecureRandomDataDynamicContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

  private static final String BEAN_NAME_FORMAT = "%s_%s";
  private static final String RANDOM_DATA = "RandomData";

  @Override
  public void initialize(ConfigurableApplicationContext applicationContext) {

    final ConfigurableEnvironment environment = applicationContext.getEnvironment();
    final ConfigurableListableBeanFactory beanFactory = applicationContext.getBeanFactory();

    final Optional<SecureRandomAlgorithm> optAlgorithm =
        PropertiesUtil.getEnumPropertySingleValue(
            environment,
            "cryptography.random.algorithm",
            SecureRandomAlgorithm.class);

    if (optAlgorithm.isEmpty()) {
      registerBean(beanFactory, SecureRandomAlgorithm.DEFAULT);
      return;
    }

    final SecureRandomAlgorithm algorithm = optAlgorithm.get();

    if (!Objects.equals(algorithm, SecureRandomAlgorithm.DRBG)) {
      registerBean(beanFactory, algorithm);
      return;
    }

    final Optional<Integer> optStrength =
        PropertiesUtil.getIntegerPropertySingleValue(
            environment,
            "cryptography.random.drbg.strength");

    final Optional<SecureRandomCapability> optCapability =
        PropertiesUtil.getEnumPropertySingleValue(
            environment,
            "cryptography.random.drbg.capability",
            SecureRandomCapability.class);

    final Optional<Boolean> optGeneratePersonalizationString =
        PropertiesUtil.getBooleanPropertySingleValue(
            environment,
            "cryptography.random.drbg.personalizationString.generate");

    final Optional<Integer> optPersonalizationStringLength =
        PropertiesUtil.getIntegerPropertySingleValue(
            environment,
            "cryptography.random.drbg.personalizationString.length");

    final DrbgParameters.Instantiation params = getDefaultDRBGParams();

    final int strength = optStrength.orElse(params.getStrength());
    final SecureRandomCapability capability =
        optCapability.orElse(SecureRandomCapability.valueOf(params.getCapability().name()));

    final boolean generatePersonalizationString = optGeneratePersonalizationString.orElse(false);
    if (generatePersonalizationString) {
      registerBean(
          beanFactory,
          strength,
          capability,
          optPersonalizationStringLength.orElse(16));
    } else {
      registerBean(beanFactory, strength, capability);
    }
  }

  private void registerBean(
      ConfigurableListableBeanFactory beanFactory,
      SecureRandomAlgorithm algorithm) {

    beanFactory.registerSingleton(
        String.format(BEAN_NAME_FORMAT, RANDOM_DATA, algorithm.name()),
        new JCASecureRandomDataService(algorithm));
  }

  private void registerBean(
      ConfigurableListableBeanFactory beanFactory,
      int strength,
      SecureRandomCapability capability,
      int personalizationStringLength) {

    beanFactory.registerSingleton(
        String.format(BEAN_NAME_FORMAT, RANDOM_DATA, SecureRandomAlgorithm.DRBG.name()),
        new JCASecureRandomDataService(strength, capability, personalizationStringLength));
  }

  private void registerBean(
      ConfigurableListableBeanFactory beanFactory,
      int strength,
      SecureRandomCapability capability) {

    beanFactory.registerSingleton(
        String.format(BEAN_NAME_FORMAT, RANDOM_DATA, SecureRandomAlgorithm.DRBG.name()),
        new JCASecureRandomDataService(strength, capability));
  }

  private DrbgParameters.Instantiation getDefaultDRBGParams() {
    try {
      return (DrbgParameters.Instantiation) SecureRandom.getInstance(SecureRandomAlgorithm.DRBG.name()).getParameters();
    } catch (NoSuchAlgorithmException e) {
      throw new DynamicContextInitializerException("Exception initializing SecureRandomData", e);
    }
  }
}
