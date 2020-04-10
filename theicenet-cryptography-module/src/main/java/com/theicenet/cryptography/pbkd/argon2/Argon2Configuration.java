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
package com.theicenet.cryptography.pbkd.argon2;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public final class Argon2Configuration {
  private final Argon2Type type;
  private final Argon2Version version;
  private final Integer iterations;
  private final Integer memoryPowOfTwo;
  private final Integer parallelism;

  public Argon2Configuration(
      Argon2Type type,
      Argon2Version version,
      Integer iterations,
      Integer memoryPowOfTwo,
      Integer parallelism) {
    
    this.type = type;
    this.version = version;
    this.iterations = iterations;
    this.memoryPowOfTwo = memoryPowOfTwo;
    this.parallelism = parallelism;
  }

  Argon2Type getType() {
    return type;
  }

  Argon2Version getVersion() {
    return version;
  }

  Integer getIterations() {
    return iterations;
  }

  Integer getMemoryPowOfTwo() {
    return memoryPowOfTwo;
  }

  Integer getParallelism() {
    return parallelism;
  }
}
