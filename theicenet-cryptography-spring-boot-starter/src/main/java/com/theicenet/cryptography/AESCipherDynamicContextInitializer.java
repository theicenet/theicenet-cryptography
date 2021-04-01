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

import com.theicenet.cryptography.cipher.symmetric.BlockCipherAEADModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherNonIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESAEADCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESIVCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESNonIVCipherService;
import com.theicenet.cryptography.util.PropertiesUtil;
import java.util.Set;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class AESCipherDynamicContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

  private static final String BEAN_NAME_FORMAT = "%s_%s";

  @Override
  public void initialize(ConfigurableApplicationContext applicationContext) {

    final ConfigurableEnvironment environment = applicationContext.getEnvironment();
    final ConfigurableListableBeanFactory beanFactory = applicationContext.getBeanFactory();

    final Set<BlockCipherModeOfOperation> blockModes =
        PropertiesUtil.getProperty(
            environment,
            "cryptography.cipher.symmetric.aes.blockMode",
            BlockCipherModeOfOperation.class);

    blockModes.forEach(blockMode -> registerBean(beanFactory, blockMode));
  }

  private void registerBean(
      ConfigurableListableBeanFactory beanFactory,
      BlockCipherModeOfOperation blockMode) {

    switch (blockMode) {
      case ECB:
        registerBean(beanFactory, BlockCipherNonIVModeOfOperation.ECB);
        break;
      case CBC:
      case CFB:
      case OFB:
      case CTR:
        registerBean(beanFactory, BlockCipherIVModeOfOperation.valueOf(blockMode.name()));
        break;
      case GCM:
        registerBean(beanFactory, BlockCipherIVModeOfOperation.GCM);
        registerBean(beanFactory, BlockCipherAEADModeOfOperation.GCM);
        break;
    }
  }

  private void registerBean(
      ConfigurableListableBeanFactory beanFactory,
      BlockCipherNonIVModeOfOperation blockMode) {

    beanFactory.registerSingleton(
        String.format(BEAN_NAME_FORMAT, "AESNonIVCipher", blockMode),
        new JCAAESNonIVCipherService(blockMode));
  }

  private void registerBean(
      ConfigurableListableBeanFactory beanFactory,
      BlockCipherIVModeOfOperation blockMode) {

    beanFactory.registerSingleton(
        String.format(BEAN_NAME_FORMAT, "AESIVCipher", blockMode),
        new JCAAESIVCipherService(blockMode));
  }

  private void registerBean(
      ConfigurableListableBeanFactory beanFactory,
      BlockCipherAEADModeOfOperation blockMode) {

    beanFactory.registerSingleton(
        String.format(BEAN_NAME_FORMAT, "AESAEADCipher", blockMode),
        new JCAAESAEADCipherService(blockMode));
  }
}
