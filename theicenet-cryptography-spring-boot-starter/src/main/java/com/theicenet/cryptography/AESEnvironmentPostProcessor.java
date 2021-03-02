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

import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVModeOfOperation;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class AESEnvironmentPostProcessor implements EnvironmentPostProcessor {

  @Override
  public void postProcessEnvironment(
      ConfigurableEnvironment environment,
      SpringApplication application) {

    final Set<BlockCipherIVModeOfOperation> blockModes =
        Optional.ofNullable(
            environment.getProperty(
                "cryptography.cipher.symmetric.aes.blockMode",
                String.class))
            .map(blockModesConfig -> blockModesConfig.split(","))
            .map(Arrays::stream)
            .map(blockModesConfigStream ->
                blockModesConfigStream
                    .map(String::trim)
                    .map(BlockCipherIVModeOfOperation::valueOf)
                    .collect(Collectors.toUnmodifiableSet()))
            .orElse(Collections.emptySet());

    application.addInitializers(new AESApplicationContextInitializer(blockModes));
  }
}
