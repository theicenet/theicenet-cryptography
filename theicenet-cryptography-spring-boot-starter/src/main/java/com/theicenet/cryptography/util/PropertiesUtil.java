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
package com.theicenet.cryptography.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public final class PropertiesUtil {
  private PropertiesUtil() {}

  public static <T extends Enum<T>> Set<T> getProperty(
      ConfigurableEnvironment environment,
      String propertyPath,
      Class<T> enumType) {

    return Optional.ofNullable(
        environment.getProperty(propertyPath, String.class))
        .map(propertyValues -> propertyValues.split(","))
        .map(Arrays::stream)
        .map(propertyValuesStream ->
            propertyValuesStream
                .map(String::trim)
                .map(value -> Enum.valueOf(enumType, value))
                .collect(Collectors.toUnmodifiableSet()))
        .orElse(Collections.emptySet());
  }
}
