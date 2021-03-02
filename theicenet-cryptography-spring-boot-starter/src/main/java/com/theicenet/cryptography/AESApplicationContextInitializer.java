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

import static java.util.Objects.isNull;

import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESIVCipherService;
import java.util.Collection;
import java.util.Set;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class AESApplicationContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

  private final Set<BlockCipherIVModeOfOperation> blockModes;

  public AESApplicationContextInitializer(
      Set<BlockCipherIVModeOfOperation> blockModes) {
    this.blockModes = blockModes;
  }

  @Override
  public void initialize(ConfigurableApplicationContext applicationContext) {
    final ConfigurableListableBeanFactory factory = applicationContext.getBeanFactory();

    if (isNull(blockModes)) {
      return;
    }

    blockModes.forEach(blockMode -> registerBean(factory, blockMode));
  }

  private void registerBean(
      ConfigurableListableBeanFactory factory,
      BlockCipherIVModeOfOperation blockMode) {

    final String beanName = String.format("%s_%s", "AESIVCipher", blockMode);
    final SymmetricIVCipherService beanInstance = new JCAAESIVCipherService(blockMode);

    factory.registerSingleton(beanName, beanInstance);
  }
}
